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
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"strings"
	"time"

	"github.com/redcarbon-dev/argus/pkg/audit"
	"github.com/redcarbon-dev/argus/pkg/auth"
	"github.com/redcarbon-dev/argus/pkg/daemon"
)

// maxBodyBytes bounds the JSON-RPC payload we read into memory.
const maxBodyBytes = 8 << 20 // 8 MiB

// endpointPath is the single MCP endpoint (Streamable HTTP transport).
const endpointPath = "/mcp"

// Options carries the channel's resolved configuration.
type Options struct {
	Addr string // HTTP listen address
}

// Server is the MCP channel. It holds only the shared DaemonContext and its
// listen options; per-request identity is resolved on the wire, never cached.
type Server struct {
	dc   *daemon.Context
	opts Options
}

// NewServer builds the channel over the shared DaemonContext.
func NewServer(dc *daemon.Context, opts Options) *Server {
	return &Server{dc: dc, opts: opts}
}

// Name implements daemon.Channel.
func (s *Server) Name() string { return "mcp" }

// Start listens for MCP requests until ctx is cancelled.
func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc(endpointPath, s.handle)
	srv := &http.Server{Addr: s.opts.Addr, Handler: mux}

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("mcp: listen %s: %w", s.opts.Addr, err)
	}
	return nil
}

// handle is the MCP endpoint: authenticate → parse JSON-RPC → dispatch. Auth
// happens before any work, so an unresolved/missing token never reaches the
// protocol layer (no anonymous access to org knowledge).
func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
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

	resp, respond := s.dispatch(r.Context(), principal, req)
	if !respond {
		// A notification expects no body (JSON-RPC 2.0 §4.1).
		w.WriteHeader(http.StatusAccepted)
		return
	}
	writeResponse(w, resp)
}

// dispatch routes one JSON-RPC message for an already-authenticated Principal.
// The bool reports whether a response should be written (false for
// notifications). Every authenticated call is attributed to the Person in the
// audit log so MCP actions are traceable like any other channel.
func (s *Server) dispatch(_ context.Context, principal auth.Principal, req rpcRequest) (rpcResponse, bool) {
	s.audit("mcp_request", principal, map[string]any{"method": req.Method})

	// A notification expects no response whatever its method (JSON-RPC 2.0 §4.1):
	// it is still processed (and audited above), but nothing is written back. This
	// covers notifications/initialized and any future client-side notification.
	if req.isNotification() {
		return rpcResponse{}, false
	}

	switch req.Method {
	case "initialize":
		return s.handleInitialize(req), true
	case "ping":
		return result(req.ID, map[string]any{}), true
	default:
		return errorResponse(req.ID, codeMethodNotFound, "method not found: "+req.Method), true
	}
}

// handleInitialize answers the MCP handshake: advertise the protocol version and
// the (currently empty) capability set, and identify the server. Slice 1 reads
// nothing from the params — the coarse capabilities arrive in later slices.
func (s *Server) handleInitialize(req rpcRequest) rpcResponse {
	return result(req.ID, initializeResult{
		ProtocolVersion: protocolVersion,
		Capabilities:    map[string]any{},
		ServerInfo:      serverInfo{Name: serverName, Version: serverVersion},
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

// compile-time check that the channel satisfies daemon.Channel.
var _ daemon.Channel = (*Server)(nil)
