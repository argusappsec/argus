package uds

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/redcarbon-dev/argus/pkg/audit"
	"github.com/redcarbon-dev/argus/pkg/auth"
	"github.com/redcarbon-dev/argus/pkg/budget"
	"github.com/redcarbon-dev/argus/pkg/daemon"
	"github.com/redcarbon-dev/argus/pkg/provider"
	"github.com/redcarbon-dev/argus/pkg/report"
	"github.com/redcarbon-dev/argus/pkg/skill"
	"github.com/redcarbon-dev/argus/pkg/soul"
)

// scriptedProvider returns canned responses in order, optionally gated.
type scriptedProvider struct {
	mu        sync.Mutex
	responses []provider.Response
	calls     int
	gate      chan struct{}
}

func (f *scriptedProvider) Generate(ctx context.Context, _ provider.Request) (provider.Response, error) {
	if f.gate != nil {
		select {
		case <-f.gate:
		case <-ctx.Done():
			return provider.Response{}, ctx.Err()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	i := f.calls
	if i >= len(f.responses) {
		i = len(f.responses) - 1
	}
	f.calls++
	return f.responses[i], nil
}

// startServer spins up a full daemon context + UDS server on a short temp
// socket path and returns the path. Everything is torn down with the test.
func startServer(t *testing.T, prov provider.Provider) (socketPath string, dc *daemon.Context) {
	t.Helper()
	home := t.TempDir()

	aud, err := audit.NewLogger(filepath.Join(home, "audit.log.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { aud.Close() })

	socketPath = shortSocketPath(t)

	dc = &daemon.Context{
		Home:         home,
		DefaultModel: "gemini-2.5-flash",
		SocketPath:   socketPath,
		Pricing:      budget.Pricing{"gemini-2.5-flash": {InputUSDPer1M: 1, OutputUSDPer1M: 2}},
		Auth:         auth.NewResolver(filepath.Join(home, "users.yaml")),
		Audit:        aud,
		Reports:      report.NewWriter(filepath.Join(home, "reports")),
		Skills:       skill.NewCatalog(skill.Builtin(), filepath.Join(home, "skills")),
		NewProvider: func(_ context.Context, _ string) (provider.Provider, error) {
			return prov, nil
		},
		LoadSoul:   func() (*soul.Soul, error) { return &soul.Soul{}, nil },
		LoadMemory: func() (string, error) { return "", nil },
	}
	dc.Sessions = daemon.NewSessionManager(dc, 2)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	srv := NewServer(dc)
	errc := make(chan error, 1)
	go func() { errc <- srv.Start(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-errc:
		case <-time.After(2 * time.Second):
			t.Error("server did not stop")
		}
	})

	// Wait for the socket to appear.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(socketPath); err == nil {
			return socketPath, dc
		}
		if time.Now().After(deadline) {
			t.Fatal("socket never appeared")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// shortSocketPath returns a socket path short enough for macOS's ~104-byte
// sun_path cap — t.TempDir() embeds the full test name and easily exceeds it.
func shortSocketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "uds")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "s.sock")
}

func textOnly(text string) provider.Response {
	return provider.Response{Text: text, Usage: provider.Usage{InputTokens: 10, OutputTokens: 5}}
}

// collectUntilTerminal drains frames until done or error.
func collectUntilTerminal(t *testing.T, c *Client) []Frame {
	t.Helper()
	var out []Frame
	for {
		f, err := c.Recv()
		if err != nil {
			t.Fatalf("Recv: %v", err)
		}
		out = append(out, f)
		if f.Type == TypeDone || f.Type == TypeError {
			return out
		}
	}
}

func TestEndToEnd_MessageRoundTrip(t *testing.T) {
	path, _ := startServer(t, &scriptedProvider{responses: []provider.Response{textOnly("ciao!")}})

	c, err := Dial(path, HelloOptions{})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	if c.SessionID() == "" {
		t.Error("hello_ok carried no session id")
	}
	if err := c.SendMessage("hello over the wire"); err != nil {
		t.Fatal(err)
	}

	frames := collectUntilTerminal(t, c)
	last := frames[len(frames)-1]
	if last.Type != TypeDone {
		t.Fatalf("terminal frame = %+v, want done", last)
	}

	var sawAgentText, sawUsage bool
	for _, f := range frames {
		if f.Type == TypeAgentMessage && f.Message != nil && f.Message.Content == "ciao!" {
			sawAgentText = true
		}
		if f.Type == TypeUsage && f.InputTokens == 10 && f.CostUSD > 0 {
			sawUsage = true
		}
	}
	if !sawAgentText {
		t.Errorf("agent text never streamed; frames: %+v", frames)
	}
	if !sawUsage {
		t.Errorf("usage frame missing or cost not computed; frames: %+v", frames)
	}
}

func TestEndToEnd_ProtocolMismatchRejected(t *testing.T) {
	path, _ := startServer(t, &scriptedProvider{responses: []provider.Response{textOnly("x")}})

	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	w := newFrameWriter(conn)
	r := newFrameReader(conn)

	if err := w.write(Frame{Type: TypeHello, Protocol: 99}); err != nil {
		t.Fatal(err)
	}
	f, err := r.read()
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != TypeRejected || !strings.Contains(f.Reason, "protocol mismatch") {
		t.Fatalf("got %+v, want protocol-mismatch rejection", f)
	}
}

func TestEndToEnd_ResumeRejected(t *testing.T) {
	path, _ := startServer(t, &scriptedProvider{responses: []provider.Response{textOnly("x")}})

	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	w := newFrameWriter(conn)
	r := newFrameReader(conn)

	if err := w.write(Frame{Type: TypeHello, Protocol: ProtocolVersion, Session: "old-session"}); err != nil {
		t.Fatal(err)
	}
	f, err := r.read()
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != TypeRejected || !strings.Contains(f.Reason, "resume not supported") {
		t.Fatalf("got %+v, want resume rejection", f)
	}
}

func TestEndToEnd_SessionCapRejected(t *testing.T) {
	path, _ := startServer(t, &scriptedProvider{responses: []provider.Response{textOnly("x")}})

	c1, err := Dial(path, HelloOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()
	c2, err := Dial(path, HelloOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()

	_, err = Dial(path, HelloOptions{})
	var rej *ErrRejected
	if !errors.As(err, &rej) || !strings.Contains(rej.Reason, "too many concurrent sessions") {
		t.Fatalf("third dial err = %v, want cap rejection", err)
	}

	// Closing a connection frees its slot.
	c1.Close()
	deadline := time.Now().Add(2 * time.Second)
	for {
		c4, err := Dial(path, HelloOptions{})
		if err == nil {
			c4.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("slot never freed: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestEndToEnd_SecondMessageWhileRunning(t *testing.T) {
	gate := make(chan struct{})
	path, _ := startServer(t, &scriptedProvider{responses: []provider.Response{textOnly("slow")}, gate: gate})

	c, err := Dial(path, HelloOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if err := c.SendMessage("first"); err != nil {
		t.Fatal(err)
	}
	if err := c.SendMessage("second while busy"); err != nil {
		t.Fatal(err)
	}

	// The second dispatch must be rejected with an error frame...
	f, err := c.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != TypeError || !strings.Contains(f.Reason, "already in progress") {
		t.Fatalf("got %+v, want run-in-progress error", f)
	}

	// ...and the first run still completes once the provider unblocks.
	close(gate)
	frames := collectUntilTerminal(t, c)
	if frames[len(frames)-1].Type != TypeDone {
		t.Fatalf("first run did not finish cleanly: %+v", frames)
	}
}

func TestEndToEnd_CancelAbortsRunKeepsSession(t *testing.T) {
	gate := make(chan struct{})
	defer close(gate)
	prov := &scriptedProvider{responses: []provider.Response{textOnly("never")}, gate: gate}
	path, _ := startServer(t, prov)

	c, err := Dial(path, HelloOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if err := c.SendMessage("long task"); err != nil {
		t.Fatal(err)
	}
	// Give the dispatch a moment to enter the gated Generate.
	time.Sleep(50 * time.Millisecond)
	if err := c.Cancel(); err != nil {
		t.Fatal(err)
	}

	f, err := c.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != TypeError || f.Reason != "cancelled" {
		t.Fatalf("got %+v, want cancelled error frame", f)
	}

	// The Session survives: a new message on the same connection works.
	prov.mu.Lock()
	prov.gate = nil
	prov.mu.Unlock()
	if err := c.SendMessage("after cancel"); err != nil {
		t.Fatal(err)
	}
	frames := collectUntilTerminal(t, c)
	if frames[len(frames)-1].Type != TypeDone {
		t.Fatalf("post-cancel run failed: %+v", frames)
	}
}

func TestEndToEnd_StaleSocketIsReplaced(t *testing.T) {
	home := t.TempDir()
	stale := shortSocketPath(t)
	// Plant a dead socket file.
	ln, err := net.Listen("unix", stale)
	if err != nil {
		t.Fatal(err)
	}
	ln.Close() // net removes the file on Close...
	if err := os.WriteFile(stale, nil, 0o600); err != nil {
		t.Fatal(err) // ...so re-plant a bogus file to simulate the crash leftover
	}

	aud, _ := audit.NewLogger(filepath.Join(home, "audit.log.jsonl"))
	t.Cleanup(func() { aud.Close() })
	dc := &daemon.Context{
		Home: home, DefaultModel: "m", SocketPath: stale,
		Auth: auth.NewResolver(filepath.Join(home, "users.yaml")), Audit: aud,
		Reports: report.NewWriter(filepath.Join(home, "reports")),
		Skills:  skill.NewCatalog(skill.Builtin(), filepath.Join(home, "skills")),
		NewProvider: func(_ context.Context, _ string) (provider.Provider, error) {
			return &scriptedProvider{responses: []provider.Response{textOnly("x")}}, nil
		},
		LoadSoul:   func() (*soul.Soul, error) { return &soul.Soul{}, nil },
		LoadMemory: func() (string, error) { return "", nil },
	}
	dc.Sessions = daemon.NewSessionManager(dc, 1)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- NewServer(dc).Start(ctx) }()

	deadline := time.Now().Add(2 * time.Second)
	for {
		if c, err := Dial(stale, HelloOptions{}); err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("server never came up over the stale socket")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-errc; err != nil {
		t.Fatalf("Start returned: %v", err)
	}
}
