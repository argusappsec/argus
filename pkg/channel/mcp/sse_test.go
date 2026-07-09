package mcp

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/argusappsec/argus/pkg/auth"
	"github.com/argusappsec/argus/pkg/provider"
)

// A tools/call from an SSE-capable client streams: the response comes back as an
// SSE "message" event with the JSON-RPC payload, not a single application/json
// body. This is what lets a long review survive client/proxy idle timeouts.
func TestServeSSE_DeliversFinalResponseAsEvent(t *testing.T) {
	s, _ := reviewServer(t, &scriptedProvider{responses: textAnswer("Log4Shell does not affect us.")}, auth.RoleAnalyst)

	req := httptest.NewRequest("POST", endpointPath, strings.NewReader(
		`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"consult","arguments":{"question":"Does Log4Shell affect us?"}}}`))
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("Accept", "application/json, text/event-stream")
	rec := httptest.NewRecorder()

	s.handle(rec, req)

	if ct := rec.Header().Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("content-type = %q, want text/event-stream", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "event: message") {
		t.Fatalf("expected an SSE message event, got: %q", body)
	}
	if !strings.Contains(body, `"id":7`) || !strings.Contains(body, "Log4Shell") {
		t.Fatalf("SSE stream missing the tool response: %q", body)
	}
}

// panicProvider aborts the agent run mid-flight. The SSE worker runs on its own
// goroutine, outside the front door's per-request panic fence, so the channel
// must recover the panic itself or the whole daemon goes down (ADR 0015).
type panicProvider struct{}

func (panicProvider) Generate(context.Context, provider.Request) (provider.Response, error) {
	panic("scanner exploded mid-review")
}

// A panic inside a streaming tools/call is recovered into a clean JSON-RPC
// error rather than crashing the daemon: the test process surviving is the
// isolation guarantee, and the client still gets a well-formed error frame.
func TestServeSSE_PanicIsRecoveredNotFatal(t *testing.T) {
	s, _ := reviewServer(t, panicProvider{}, auth.RoleAnalyst)

	req := httptest.NewRequest("POST", endpointPath, strings.NewReader(
		`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"consult","arguments":{"question":"boom?"}}}`))
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("Accept", "text/event-stream")
	rec := httptest.NewRecorder()

	s.handle(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, "event: message") || !strings.Contains(body, `"error"`) {
		t.Fatalf("expected a JSON-RPC error delivered over SSE, got: %q", body)
	}
	if !strings.Contains(body, `"id":9`) {
		t.Fatalf("error must echo the request id: %q", body)
	}
}

// Without an Accept: text/event-stream header the client keeps the single
// application/json response — SSE is opt-in, existing clients are unaffected.
func TestServeSSE_FallsBackToJSONWithoutAcceptHeader(t *testing.T) {
	s, _ := reviewServer(t, &scriptedProvider{responses: textAnswer("ok")}, auth.RoleAnalyst)

	rec := post(t, s, testToken,
		`{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"consult","arguments":{"question":"Anything?"}}}`)

	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type = %q, want application/json", ct)
	}
	if strings.Contains(rec.Body.String(), "event: message") {
		t.Fatalf("non-SSE client must not get an SSE stream: %q", rec.Body.String())
	}
}

func TestAcceptsSSE(t *testing.T) {
	mk := func(accept string) bool {
		r := httptest.NewRequest("POST", endpointPath, nil)
		if accept != "" {
			r.Header.Set("Accept", accept)
		}
		return acceptsSSE(r)
	}
	if !mk("application/json, text/event-stream") {
		t.Error("should accept when text/event-stream is listed")
	}
	if mk("application/json") {
		t.Error("should not accept a json-only client")
	}
	if mk("") {
		t.Error("should not accept an empty Accept")
	}
}

func TestParseProgressToken(t *testing.T) {
	with := func(params string) json.RawMessage {
		return parseProgressToken(rpcRequest{Params: json.RawMessage(params)})
	}
	if tok := with(`{"_meta":{"progressToken":"abc"}}`); string(tok) != `"abc"` {
		t.Errorf("string token = %s, want \"abc\"", tok)
	}
	if tok := with(`{"_meta":{"progressToken":42}}`); string(tok) != `42` {
		t.Errorf("number token = %s, want 42", tok)
	}
	if tok := with(`{"name":"consult"}`); tok != nil {
		t.Errorf("absent token should be nil, got %s", tok)
	}
}

// With a progressToken the heartbeat carries an MCP notifications/progress
// message (resets the client's own timeout); without one it is just an SSE
// comment (resets proxy idle timers only).
func TestWriteSSEHeartbeat(t *testing.T) {
	var withTok strings.Builder
	writeSSEHeartbeat(&withTok, json.RawMessage(`"tok-1"`), 3)
	if !strings.Contains(withTok.String(), "notifications/progress") || !strings.Contains(withTok.String(), "tok-1") {
		t.Errorf("heartbeat with token must emit a progress notification: %q", withTok.String())
	}

	var noTok strings.Builder
	writeSSEHeartbeat(&noTok, nil, 1)
	if strings.Contains(noTok.String(), "notifications/progress") {
		t.Errorf("heartbeat without token must not emit a progress message: %q", noTok.String())
	}
	if !strings.HasPrefix(noTok.String(), ":") {
		t.Errorf("heartbeat without token must be an SSE comment: %q", noTok.String())
	}
}
