package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/argusappsec/argus/pkg/auth"
)

// sseHeartbeatInterval is how often a streaming tool call emits a keep-alive
// while the agent runs. Kept well under common 30–60s client/proxy idle
// timeouts so a long review never looks dead.
const sseHeartbeatInterval = 15 * time.Second

// acceptsSSE reports whether the client is willing to receive a Server-Sent
// Events stream (the Streamable HTTP transport), i.e. its Accept header lists
// text/event-stream.
func acceptsSSE(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "text/event-stream")
}

// serveToolCallSSE runs a long tools/call (review/consult) while streaming
// Server-Sent Events: periodic keep-alives hold the connection open past
// client/proxy idle timeouts, then the JSON-RPC response is delivered as the
// final SSE message. The agent runs in a goroutine; if the client disconnects,
// the request context cancels and the run unwinds. A tools/call never mints a
// session, so no session header is returned on this path.
func (s *Server) serveToolCallSSE(ctx context.Context, w http.ResponseWriter, principal auth.Principal, sessionID string, req rpcRequest) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		// The writer cannot stream — fall back to one buffered JSON response.
		resp, respond, _ := s.dispatch(ctx, principal, sessionID, req)
		if respond {
			writeResponse(w, resp)
		}
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // stop nginx buffering so events flush promptly
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	progressToken := parseProgressToken(req)

	// Buffered so the worker never blocks delivering its result even if we have
	// already returned on context cancellation.
	done := make(chan rpcResponse, 1)
	go func() {
		// A tools/call always responds and never mints a session, so the respond
		// bool and the new-session id are not needed here.
		resp, _, _ := s.dispatch(ctx, principal, sessionID, req)
		done <- resp
	}()

	ticker := time.NewTicker(sseHeartbeatInterval)
	defer ticker.Stop()
	var steps int
	for {
		select {
		case <-ctx.Done():
			return // client gone; the dispatch goroutine unwinds on the same ctx
		case resp := <-done:
			writeSSEMessage(w, resp)
			flusher.Flush()
			return
		case <-ticker.C:
			steps++
			writeSSEHeartbeat(w, progressToken, steps)
			flusher.Flush()
		}
	}
}

// writeSSEMessage frames one JSON-RPC message as an SSE "message" event.
func writeSSEMessage(w io.Writer, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	fmt.Fprintf(w, "event: message\ndata: %s\n\n", b)
}

// writeSSEHeartbeat keeps the stream alive while the agent runs. It always emits
// an SSE comment (resets proxy idle timers without being a protocol message),
// and — only when the client supplied a progressToken (MCP progress spec) — an
// MCP notifications/progress message so the client's own tool-call timeout
// resets too.
func writeSSEHeartbeat(w io.Writer, progressToken json.RawMessage, step int) {
	fmt.Fprint(w, ": keep-alive\n\n")
	if len(progressToken) == 0 {
		return
	}
	params, err := json.Marshal(map[string]any{
		"progressToken": progressToken,
		"progress":      step,
		"message":       "Argus is working…",
	})
	if err != nil {
		return
	}
	writeSSEMessage(w, map[string]any{
		"jsonrpc": "2.0",
		"method":  "notifications/progress",
		"params":  json.RawMessage(params),
	})
}

// parseProgressToken extracts the MCP progress token a client may attach under
// params._meta.progressToken. The spec allows a string or a number, so it is
// kept raw. Returns nil when absent or unparseable.
func parseProgressToken(req rpcRequest) json.RawMessage {
	if len(req.Params) == 0 {
		return nil
	}
	var p struct {
		Meta struct {
			ProgressToken json.RawMessage `json:"progressToken"`
		} `json:"_meta"`
	}
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return nil
	}
	return p.Meta.ProgressToken
}
