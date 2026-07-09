package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/argusappsec/argus/pkg/audit"
)

// Route binds a fixed, well-known path to an HTTP handler on the front door
// (ADR 0015). A path-bound Channel returns its routes; the front door mounts
// each one behind a per-request panic fence.
type Route struct {
	Pattern string
	Handler http.Handler
}

// HTTPChannel is a path-bound Channel: instead of owning a listener it
// contributes fixed routes to the daemon's single HTTP front door (ADR 0015).
// This is the amendment to ADR 0004 — a Channel owns its transport (Unix
// socket, future Slack WS) *or* registers a path on the front door. The
// classic Channel contract (Name/Start) still governs loop-owning transports;
// path-bound channels ride the front door's per-request recovery instead of
// restart-with-backoff.
type HTTPChannel interface {
	Name() string
	Routes() []Route
}

// frontDoorName is the loop-owning Channel name the front door reports; its
// panics and errors are audited under it like any other channel.
const frontDoorName = "http"

// FrontDoor is the daemon's single HTTP listener (ADR 0015): it serves the
// fixed paths every configured HTTP channel registers, plus its own /healthz
// probe, on one address (daemon.http_addr). It is itself a loop-owning
// Channel — RunChannels restarts it with backoff if the listener dies — while
// each channel handler runs behind a per-request recovery fence so one
// channel's panic degrades neither another channel nor the daemon.
type FrontDoor struct {
	dc       *Context
	addr     string
	channels []HTTPChannel
}

// NewFrontDoor builds the front door for the given address and the HTTP
// channels whose paths it serves. It is constructed only when at least one
// HTTP channel is configured, keeping a minimal install socket-only.
func NewFrontDoor(dc *Context, addr string, channels ...HTTPChannel) *FrontDoor {
	return &FrontDoor{dc: dc, addr: addr, channels: channels}
}

// Name implements daemon.Channel.
func (f *FrontDoor) Name() string { return frontDoorName }

// Handler builds the mux the front door serves: /healthz plus every channel's
// fixed routes, each fenced by per-request recovery. Exposed so tests can
// drive it through httptest without binding a real port.
func (f *FrontDoor) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	})
	for _, ch := range f.channels {
		for _, rt := range ch.Routes() {
			mux.Handle(rt.Pattern, f.fence(ch.Name(), rt.Handler))
		}
	}
	return mux
}

// Start serves the front door until ctx is cancelled. It refuses to start with
// no channels — the daemon never constructs it in that case, so a listener is
// bound only when there is something to serve.
func (f *FrontDoor) Start(ctx context.Context) error {
	if len(f.channels) == 0 {
		return errors.New("http: front door has no channels to serve")
	}
	// ReadHeaderTimeout bounds slow-header clients; WriteTimeout is left unset
	// because an MCP Repo/Snapshot review is a long synchronous run that a
	// write deadline would cut off (long runs stream over SSE instead).
	srv := &http.Server{Addr: f.addr, Handler: f.Handler(), ReadHeaderTimeout: 10 * time.Second}

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("http: listen %s: %w", f.addr, err)
	}
	return nil
}

// fence wraps one channel's handler in a per-request recovery: a panic is
// audited as channel_panic and answered with a 500, so it never crosses into
// another channel's handler or brings the listener down (ADR 0004 as amended
// by ADR 0015).
func (f *FrontDoor) fence(channel string, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				if f.dc.Audit != nil {
					_ = f.dc.Audit.Log(audit.Event{Type: "channel_panic", Data: map[string]any{
						"channel": channel,
						"panic":   fmt.Sprint(rec),
					}})
				}
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
		}()
		h.ServeHTTP(w, r)
	})
}

// compile-time check that the front door is itself a loop-owning Channel.
var _ Channel = (*FrontDoor)(nil)
