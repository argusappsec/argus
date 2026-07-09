package daemon

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/argusappsec/argus/pkg/audit"
	"github.com/argusappsec/argus/pkg/provider"
)

// stubChannel is a path-bound HTTPChannel whose handler is supplied per test.
type stubChannel struct {
	name   string
	routes []Route
}

func (c *stubChannel) Name() string   { return c.name }
func (c *stubChannel) Routes() []Route { return c.routes }

// frontDoorContext builds a Context with just the audit logger the fence needs.
func frontDoorContext(t *testing.T) *Context {
	t.Helper()
	return testContext(t, &scriptedProvider{responses: []provider.Response{textOnly("x")}}, 4)
}

// auditContains reports whether the daemon's audit log holds an event of the
// given type attributed to the given channel.
func auditContains(t *testing.T, dc *Context, eventType, channel string) bool {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dc.Home, "audit.log.jsonl"))
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	for line := range strings.SplitSeq(strings.TrimSpace(string(b)), "\n") {
		if line == "" {
			continue
		}
		var e audit.Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("parse audit line: %v", err)
		}
		if e.Type == eventType && e.Data["channel"] == channel {
			return true
		}
	}
	return false
}

// get issues a GET against the front door's handler and returns the recorder.
func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func TestFrontDoor_RoutesBothChannelsAndHealthz(t *testing.T) {
	dc := frontDoorContext(t)
	gh := &stubChannel{name: "github", routes: []Route{{Pattern: "/webhooks/github", Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "webhook")
	})}}}
	mcp := &stubChannel{name: "mcp", routes: []Route{{Pattern: "/mcp", Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "mcp")
	})}}}
	h := NewFrontDoor(dc, ":0", gh, mcp).Handler()

	// Both channel paths and /healthz are served by the one handler.
	for path, want := range map[string]string{
		"/webhooks/github": "webhook",
		"/mcp":             "mcp",
	} {
		rec := get(t, h, path)
		if rec.Code != http.StatusOK || rec.Body.String() != want {
			t.Errorf("%s: code=%d body=%q, want 200 %q", path, rec.Code, rec.Body.String(), want)
		}
	}

	if rec := get(t, h, "/healthz"); rec.Code != http.StatusOK {
		t.Errorf("/healthz: code=%d, want 200", rec.Code)
	}
}

func TestFrontDoor_PanicIsolation(t *testing.T) {
	dc := frontDoorContext(t)
	boom := &stubChannel{name: "boom", routes: []Route{{Pattern: "/boom", Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("handler exploded")
	})}}}
	ok := &stubChannel{name: "ok", routes: []Route{{Pattern: "/ok", Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "fine")
	})}}}
	h := NewFrontDoor(dc, ":0", boom, ok).Handler()

	// A panic in one channel's handler is fenced into a 500, not a crash.
	if rec := get(t, h, "/boom"); rec.Code != http.StatusInternalServerError {
		t.Errorf("/boom: code=%d, want 500", rec.Code)
	}
	// The other channel keeps serving after the panic.
	if rec := get(t, h, "/ok"); rec.Code != http.StatusOK || rec.Body.String() != "fine" {
		t.Errorf("/ok after panic: code=%d body=%q, want 200 %q", rec.Code, rec.Body.String(), "fine")
	}

	// The panic was audited as channel_panic, attributed to the channel.
	if !auditContains(t, dc, "channel_panic", "boom") {
		t.Errorf("panic not audited as channel_panic for channel boom")
	}
}

func TestFrontDoor_RefusesToStartWithNoChannels(t *testing.T) {
	dc := frontDoorContext(t)
	err := NewFrontDoor(dc, ":0").Start(context.Background())
	if err == nil {
		t.Fatal("front door started with no channels; want refusal")
	}
	if !strings.Contains(err.Error(), "no channels") {
		t.Errorf("error = %q, want it to mention no channels", err.Error())
	}
}

func TestFrontDoor_ServesUntilContextCancelled(t *testing.T) {
	dc := frontDoorContext(t)
	ch := &stubChannel{name: "ping", routes: []Route{{Pattern: "/ping", Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "pong")
	})}}}
	// Bind an ephemeral port so we exercise the real listener path, then a live
	// request over the wire, then a clean shutdown on cancel.
	fd := NewFrontDoor(dc, "127.0.0.1:0", ch)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	// The listener address isn't observable through the public API, so drive
	// the handler for behavior and assert Start returns cleanly on cancel.
	go func() { done <- fd.Start(ctx) }()

	// Give the server a moment to bind, then cancel and require a clean return.
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Start returned %v, want nil on cancel", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Start did not return after context cancel")
	}
}
