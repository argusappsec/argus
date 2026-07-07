package uds

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"strconv"
	"sync"
	"time"

	"github.com/argusappsec/argus/pkg/audit"
	"github.com/argusappsec/argus/pkg/auth"
	"github.com/argusappsec/argus/pkg/daemon"
	"github.com/argusappsec/argus/pkg/provider"
)

// helloTimeout bounds how long a fresh connection may take to present its
// hello frame before being dropped.
const helloTimeout = 10 * time.Second

// Server is the UDS Channel implementation. One instance per daemon; one
// goroutine per accepted connection.
type Server struct {
	dc   *daemon.Context
	path string
}

// NewServer creates the channel listening on dc.SocketPath.
func NewServer(dc *daemon.Context) *Server {
	return &Server{dc: dc, path: dc.SocketPath}
}

// Name implements daemon.Channel.
func (s *Server) Name() string { return "uds" }

// ErrAlreadyRunning is returned when another daemon already serves the socket.
var ErrAlreadyRunning = errors.New("uds: a daemon is already listening on this socket")

// Start listens on the socket and serves connections until ctx is cancelled.
// A stale socket file (left by a crashed daemon) is detected by attempting a
// connect: refused → unlink and rebind; accepted → ErrAlreadyRunning.
func (s *Server) Start(ctx context.Context) error {
	if _, err := os.Stat(s.path); err == nil {
		probe, dialErr := net.DialTimeout("unix", s.path, time.Second)
		if dialErr == nil {
			probe.Close()
			return fmt.Errorf("%w: %s", ErrAlreadyRunning, s.path)
		}
		if err := os.Remove(s.path); err != nil {
			return fmt.Errorf("uds: remove stale socket: %w", err)
		}
	}

	ln, err := net.Listen("unix", s.path)
	if err != nil {
		return fmt.Errorf("uds: listen %s: %w", s.path, err)
	}
	// Possession of the socket is authentication (ADR 0007): owner-only.
	if err := os.Chmod(s.path, 0o600); err != nil {
		ln.Close()
		return fmt.Errorf("uds: chmod socket: %w", err)
	}

	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	defer os.Remove(s.path)

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil // clean shutdown
			}
			return fmt.Errorf("uds: accept: %w", err)
		}
		go s.handleConn(ctx, conn.(*net.UnixConn))
	}
}

// handleConn drives one client connection = one Session (created at connect,
// destroyed at disconnect; an in-flight run dies with it).
func (s *Server) handleConn(ctx context.Context, conn *net.UnixConn) {
	defer conn.Close()
	defer func() {
		// A panic in agent.Run (or anywhere in dispatch) is recovered here:
		// the connection dies, the daemon stays up (ADR 0004).
		if r := recover(); r != nil {
			_ = s.dc.Audit.Log(audit.Event{Type: "channel_panic", Data: map[string]any{
				"channel": s.Name(),
				"panic":   fmt.Sprint(r),
			}})
		}
	}()

	w := newFrameWriter(conn)
	r := newFrameReader(conn)

	// Hello must arrive promptly.
	_ = conn.SetReadDeadline(time.Now().Add(helloTimeout))
	hello, err := r.read()
	if err != nil || hello.Type != TypeHello {
		_ = w.write(Frame{Type: TypeRejected, Reason: "expected hello frame"})
		return
	}
	_ = conn.SetReadDeadline(time.Time{})

	if hello.Protocol != ProtocolVersion {
		_ = w.write(Frame{Type: TypeRejected, Reason: fmt.Sprintf(
			"protocol mismatch: server speaks v%d, client spoke v%d — update the argus binary", ProtocolVersion, hello.Protocol)})
		return
	}
	if hello.Session != "" {
		_ = w.write(Frame{Type: TypeRejected, Reason: "resume not supported"})
		return
	}

	principal, err := s.resolvePeer(conn)
	if err != nil {
		_ = w.write(Frame{Type: TypeRejected, Reason: "could not authenticate peer"})
		return
	}

	sess, _, err := s.dc.Sessions.GetOrCreate(ctx, s.Name(), daemon.NewConversationKey(), principal, daemon.SessionOptions{
		Model:    hello.Model,
		MaxTurns: hello.MaxTurns,
	})
	if err != nil {
		_ = w.write(Frame{Type: TypeRejected, Reason: rejectionReason(err)})
		return
	}
	defer s.dc.Sessions.Release(sess)

	if err := w.write(Frame{Type: TypeHelloOK, SessionID: sess.ID(), Protocol: ProtocolVersion}); err != nil {
		return
	}

	s.serve(ctx, sess, w, r)
}

// serve is the per-connection read loop. Dispatches run in a goroutine so
// cancel frames are honored while a run is in flight; the connection's
// lifetime bounds every run (disconnect → context cancelled → run dies).
//
// One run in flight per connection: the guard lives here so a rejected
// second message can never repoint cancelRun away from the live run. The
// Session has the same guard as a backstop for misbehaving channels.
func (s *Server) serve(ctx context.Context, sess *daemon.Session, w *frameWriter, r *frameReader) {
	connCtx, cancelConn := context.WithCancel(ctx)
	defer cancelConn()

	var (
		runMu     sync.Mutex
		inFlight  bool
		cancelRun context.CancelFunc = func() {}
	)
	// beginRun reserves the single run slot and installs its cancel func.
	beginRun := func() (context.Context, bool) {
		runMu.Lock()
		defer runMu.Unlock()
		if inFlight {
			return nil, false
		}
		inFlight = true
		runCtx, cancel := context.WithCancel(connCtx)
		cancelRun = cancel
		return runCtx, true
	}
	endRun := func() {
		runMu.Lock()
		inFlight = false
		runMu.Unlock()
	}
	defer func() {
		runMu.Lock()
		cancelRun()
		runMu.Unlock()
	}()

	for {
		f, err := r.read()
		if err != nil {
			return // disconnect: deferred cancel kills any in-flight run
		}

		switch f.Type {
		case TypeMessage:
			runCtx, ok := beginRun()
			if !ok {
				_ = w.write(Frame{Type: TypeError, Reason: daemon.ErrRunInProgress.Error()})
				continue
			}
			go func(text string) {
				defer endRun()
				_, err := sess.HandleMessage(runCtx, text, s.runCallbacks(w))
				s.finishRun(w, err, "", 0)
			}(f.Text)

		case TypeReview:
			runCtx, ok := beginRun()
			if !ok {
				_ = w.write(Frame{Type: TypeError, Reason: daemon.ErrRunInProgress.Error()})
				continue
			}
			go func(target daemon.ReviewTarget) {
				defer endRun()
				rep, reportPath, err := sess.HandleReview(runCtx, target, s.runCallbacks(w))
				findings := 0
				if rep != nil {
					findings = len(rep.Findings)
				}
				s.finishRun(w, err, reportPath, findings)
			}(daemon.ReviewTarget{GitHubURL: f.GitHubURL, Ref: f.Ref})

		case TypeCancel:
			runMu.Lock()
			cancelRun()
			runMu.Unlock()

		default:
			_ = w.write(Frame{Type: TypeError, Reason: fmt.Sprintf("unknown frame type %q", f.Type)})
		}
	}
}

// runCallbacks streams agent events back over the wire.
func (s *Server) runCallbacks(w *frameWriter) daemon.RunCallbacks {
	return daemon.RunCallbacks{
		OnMessage: func(m provider.Message) {
			_ = w.write(Frame{Type: TypeAgentMessage, Message: &m})
		},
		OnUsage: func(u provider.Usage, cost float64) {
			_ = w.write(Frame{Type: TypeUsage, InputTokens: u.InputTokens, OutputTokens: u.OutputTokens, CostUSD: cost})
		},
	}
}

// finishRun reports the terminal frame for one dispatch.
func (s *Server) finishRun(w *frameWriter, err error, reportPath string, findings int) {
	switch {
	case err == nil:
		_ = w.write(Frame{Type: TypeDone, ReportPath: reportPath, Findings: findings})
	case errors.Is(err, context.Canceled):
		_ = w.write(Frame{Type: TypeError, Reason: "cancelled"})
	default:
		_ = w.write(Frame{Type: TypeError, Reason: err.Error()})
	}
}

// resolvePeer derives the identity from kernel peer credentials and applies
// the channel's trust policy (ADR 0007): a known identity is attributed to
// its Person; an unknown one becomes the implicit admin. The Resolver itself
// stays strict — the fallback lives here and only here.
func (s *Server) resolvePeer(conn *net.UnixConn) (auth.Principal, error) {
	uid, err := peerUID(conn)
	if err != nil {
		return auth.Principal{}, err
	}
	username := strconv.Itoa(uid)
	if u, lookupErr := user.LookupId(strconv.Itoa(uid)); lookupErr == nil {
		username = u.Username
	}
	identity := "local:" + username

	p, err := s.dc.Auth.Resolve(identity)
	if err == nil {
		return p, nil
	}
	if errors.Is(err, auth.ErrUnknownIdentity) {
		return auth.ImplicitAdmin(identity), nil
	}
	return auth.Principal{}, err
}

// rejectionReason translates dispatch errors into the polite, opaque wire
// reason (no operational detail leaks — ADR 0003).
func rejectionReason(err error) string {
	if errors.Is(err, daemon.ErrSessionLimit) {
		return "too many concurrent sessions — try again later"
	}
	return err.Error()
}

