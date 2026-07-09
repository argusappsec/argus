// Package mcp is the MCP channel (ADR 0011): an HTTP server that lets an
// external AI consult Argus as a colleague over the Model Context Protocol.
//
// Slice 1 is the spine — it stands the server up as a daemon goroutine sharing
// the common DaemonContext (ADR 0004), authenticates the caller by bearer token
// (`auth.Resolver.ResolveMCPToken` → a Person, no anonymous access), and answers
// the MCP initialize handshake. The coarse capabilities (review, consult,
// Resources) plug into the same dispatch in later slices; the low-level scanners
// are never exposed (ADR 0011).
package mcp

import (
	"context"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"strings"
	"sync"

	"github.com/argusappsec/argus/pkg/audit"
	"github.com/argusappsec/argus/pkg/auth"
	"github.com/argusappsec/argus/pkg/daemon"
)

// maxBodyBytes bounds the JSON-RPC payload we read into memory.
const maxBodyBytes = 8 << 20 // 8 MiB

// endpointPath is the single MCP endpoint (Streamable HTTP transport). It is
// the fixed path the channel binds on the daemon's shared front door
// (ADR 0015); the channel never opens a listener of its own.
const endpointPath = "/mcp"

// Server is the MCP channel. It holds the shared DaemonContext and the live
// MCP sessions (each carrying a Snapshot workspace so follow-up reviews
// accumulate). Per-request identity is resolved on the wire, never cached.
type Server struct {
	dc *daemon.Context

	mu       sync.Mutex
	sessions map[string]*mcpSession
}

// NewServer builds the channel over the shared DaemonContext. Auth is
// per-Person bearer tokens resolved at request time, so there is nothing to
// configure here.
func NewServer(dc *daemon.Context) *Server {
	return &Server{dc: dc, sessions: map[string]*mcpSession{}}
}

// Name implements daemon.Channel.
func (s *Server) Name() string { return "mcp" }

// Routes implements daemon.HTTPChannel: MCP requests are served at the single
// well-known path on the daemon's shared front door (ADR 0015). The front door
// sets ReadHeaderTimeout and deliberately leaves WriteTimeout unset — a
// Snapshot/Repo review is a long synchronous run a write deadline would cut
// off (long reviews stream over SSE instead, see serveToolCallSSE).
func (s *Server) Routes() []daemon.Route {
	return []daemon.Route{{Pattern: endpointPath, Handler: http.HandlerFunc(s.handle)}}
}

// handle is the MCP endpoint: authenticate → parse JSON-RPC → dispatch. Auth
// happens before any work, so an unresolved/missing token never reaches the
// protocol layer (no anonymous access to org knowledge). A DELETE terminates the
// MCP session and cleans up its Snapshot workspace (Streamable HTTP transport).
func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
	case http.MethodDelete:
		s.handleDelete(w, r)
		return
	default:
		w.Header().Set("Allow", http.MethodPost+", "+http.MethodDelete)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	principal, ok := s.authenticate(w, r)
	if !ok {
		return // authenticate already wrote the 401
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
	if err != nil {
		writeResponse(w, errorResponse(nil, codeParseError, "read body"))
		return
	}

	var req rpcRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeResponse(w, errorResponse(nil, codeParseError, "parse error"))
		return
	}
	if req.JSONRPC != "2.0" {
		writeResponse(w, errorResponse(req.ID, codeInvalidRequest, "jsonrpc must be \"2.0\""))
		return
	}

	sessionID := r.Header.Get(sessionHeader)

	// A tool call (review/consult) is a long synchronous agent run. When the
	// client accepts an SSE stream, serve it as one: periodic keep-alives hold
	// the connection open past client/proxy idle timeouts, then the JSON-RPC
	// response arrives as the final SSE message.
	if req.Method == "tools/call" && !req.isNotification() && acceptsSSE(r) {
		s.serveToolCallSSE(r.Context(), w, principal, sessionID, req)
		return
	}

	resp, respond, newSession := s.dispatch(r.Context(), principal, sessionID, req)
	// initialize mints a session; hand its id back so the client echoes it on
	// later requests and its Snapshot workspace accumulates across calls.
	if newSession != "" {
		w.Header().Set(sessionHeader, newSession)
	}
	if !respond {
		// A notification expects no body (JSON-RPC 2.0 §4.1).
		w.WriteHeader(http.StatusAccepted)
		return
	}
	writeResponse(w, resp)
}

// handleDelete terminates the MCP session named by the session header, releasing
// its Snapshot workspace. It authenticates first (no anonymous teardown) and is
// idempotent: a missing or unknown session is simply a 204.
func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	id := r.Header.Get(sessionHeader)
	closed := s.closeSession(id)
	s.audit("mcp_session_closed", principal, map[string]any{"closed": closed})
	w.WriteHeader(http.StatusNoContent)
}

// dispatch routes one JSON-RPC message for an already-authenticated Principal.
// The bool reports whether a response should be written (false for
// notifications); the string is a freshly-minted MCP session id to hand back
// (non-empty only for initialize). Every authenticated call is attributed to the
// Person in the audit log so MCP actions are traceable like any other channel.
func (s *Server) dispatch(ctx context.Context, principal auth.Principal, sessionID string, req rpcRequest) (rpcResponse, bool, string) {
	s.audit("mcp_request", principal, map[string]any{"method": req.Method})

	// A notification expects no response whatever its method (JSON-RPC 2.0 §4.1):
	// it is still processed (and audited above), but nothing is written back. This
	// covers notifications/initialized and any future client-side notification.
	if req.isNotification() {
		return rpcResponse{}, false, ""
	}

	switch req.Method {
	case "initialize":
		// Open the connection's MCP session here so its Snapshot workspace can
		// accumulate across the review calls that follow.
		return s.handleInitialize(req), true, s.openSession()
	case "ping":
		return result(req.ID, map[string]any{}), true, ""
	case "tools/list":
		return s.handleToolsList(req), true, ""
	case "tools/call":
		return s.handleToolCall(ctx, principal, sessionID, req), true, ""
	case "resources/list":
		return s.handleResourcesList(principal, req), true, ""
	case "resources/read":
		return s.handleResourceRead(principal, req), true, ""
	default:
		return errorResponse(req.ID, codeMethodNotFound, "method not found: "+req.Method), true, ""
	}
}

// handleInitialize answers the MCP handshake: advertise the protocol version,
// the coarse capability set (tools — review and consult — and resources: SOUL,
// CONTEXT documents, recent reports), and identify the server. The params are not
// read — the surface is fixed by ADR 0011, not negotiated.
func (s *Server) handleInitialize(req rpcRequest) rpcResponse {
	return result(req.ID, initializeResult{
		ProtocolVersion: protocolVersion,
		Capabilities: map[string]any{
			"tools":     map[string]any{},
			"resources": map[string]any{},
		},
		ServerInfo: serverInfo{Name: serverName, Version: serverVersion},
	})
}

// authenticate resolves the inbound bearer token to a Person via the shared
// auth Resolver. A missing or unresolved token is rejected with 401 and no
// operational detail (ADR 0003) — there is no anonymous MCP access. The
// rejection is recorded in the audit log for the operator.
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) (auth.Principal, bool) {
	token := bearerToken(r.Header.Get("Authorization"))
	if token == "" {
		s.audit("mcp_unauthenticated", auth.Principal{}, map[string]any{"reason": "missing bearer token"})
		unauthorized(w)
		return auth.Principal{}, false
	}
	principal, err := s.dc.Auth.ResolveMCPToken(token)
	if err != nil {
		s.audit("mcp_unauthenticated", auth.Principal{}, map[string]any{"reason": "unresolved token"})
		unauthorized(w)
		return auth.Principal{}, false
	}
	return principal, true
}

// audit records a channel event, attributing it to the resolved Principal when
// one is known (an empty Principal is the pre-auth rejection path).
func (s *Server) audit(typ string, principal auth.Principal, extra map[string]any) {
	data := map[string]any{"channel": s.Name()}
	if principal.ID != "" {
		data["principal"] = principal.ID
		data["identity"] = principal.Identity
		data["role"] = string(principal.Role)
	}
	maps.Copy(data, extra)
	_ = s.dc.Audit.Log(audit.Event{Type: typ, Data: data})
}

// bearerToken extracts the token from an "Authorization: Bearer <token>" header,
// returning "" when the header is absent or not a bearer credential.
func bearerToken(header string) string {
	const prefix = "Bearer "
	if len(header) >= len(prefix) && strings.EqualFold(header[:len(prefix)], prefix) {
		return strings.TrimSpace(header[len(prefix):])
	}
	return ""
}

// unauthorized writes the opaque 401 strangers receive — no leak of whether a
// token was missing vs. merely unknown.
func unauthorized(w http.ResponseWriter) {
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

// writeResponse serializes a JSON-RPC response as the single-object form of the
// Streamable HTTP transport (application/json, not an SSE stream).
func writeResponse(w http.ResponseWriter, resp rpcResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// compile-time check that the channel satisfies daemon.HTTPChannel: it binds a
// path on the front door rather than owning a listener (ADR 0015).
var _ daemon.HTTPChannel = (*Server)(nil)
