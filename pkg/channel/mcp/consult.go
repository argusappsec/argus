package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"sync"

	"github.com/argusappsec/argus/pkg/auth"
	"github.com/argusappsec/argus/pkg/daemon"
	"github.com/argusappsec/argus/pkg/provider"
)

// toolConsult is the name of the consult capability (ADR 0011): org-knowledge
// Q&A that needs the organization's security context to answer.
const toolConsult = "consult"

// consultDescription is what the external AI reads to decide when to call
// consult. It scopes the tool to questions that need the organization's own
// security context — the boundary the MVP relies on (ADR 0011): generic security
// education is the caller's own job and is simply not what this surface
// advertises, not something refused at runtime.
const consultDescription = "Ask Argus — your organization's own security engineer — a question that needs YOUR " +
	"organization's security context to answer: its stack, conventions, infra, compliance posture, risk " +
	"tolerance, and the decisions and accepted false positives recorded in its knowledge base. Use this for " +
	"questions like \"does this CVE affect us?\", \"what are our auth conventions?\", or \"how do we handle " +
	"secrets?\" — answers grounded in how THIS organization builds things. Do NOT use it for textbook security " +
	"questions (\"what is a path traversal?\") you can already answer yourself."

// consultToolDecl is the consult tool's wire declaration for tools/list.
func consultToolDecl() toolDecl {
	return toolDecl{
		Name:        toolConsult,
		Description: consultDescription,
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"question": map[string]any{
					"type":        "string",
					"description": "The security question to answer using the organization's context.",
				},
			},
			"required": []string{"question"},
		},
	}
}

// consultResult is the machine-readable payload returned to the caller: the
// answer Argus produced from the organization's security knowledge.
type consultResult struct {
	Answer string `json:"answer"`
}

// canConsult reports whether role may consult Argus. Consult is read-only — it
// runs an agent turn over the org's knowledge and mutates nothing — so it is
// open to viewers as well as analysts and admins (a viewer stays read-only
// across channels: they can ask, but cannot request a review or any state
// change).
func canConsult(role auth.Role) bool {
	return role == auth.RoleAdmin || role == auth.RoleAnalyst || role == auth.RoleViewer
}

// errConsultDenied is the tool-layer refusal a caller without a consulting role
// gets, phrased so the external AI relays it to the developer.
const errConsultDenied = "permission denied: consulting Argus requires the viewer, analyst, or admin role on this channel"

// handleConsult is the consult capability: enforce RBAC at the tool layer, run
// an org-aware Q&A turn with no code target, and return the answer Argus produced
// from SOUL/MEMORY/CONTEXT. When the caller carries an MCP session the turn runs
// on that session's daemon conversation so a follow-up consult keeps context.
func (s *Server) handleConsult(ctx context.Context, principal auth.Principal, sessionID string, req rpcRequest, rawArgs json.RawMessage) rpcResponse {
	// RBAC at the tool layer so the channel cannot escalate a caller's role and
	// the refusal is uniform however the external AI phrases the request.
	if !canConsult(principal.Role) {
		s.audit("mcp_consult_denied", principal, map[string]any{"reason": "insufficient role"})
		return result(req.ID, toolError(errConsultDenied))
	}

	var args struct {
		Question string `json:"question"`
	}
	if err := json.Unmarshal(rawArgs, &args); err != nil {
		return result(req.ID, toolError("invalid consult arguments: "+err.Error()))
	}
	question := strings.TrimSpace(args.Question)
	if question == "" {
		return result(req.ID, toolError("consult requires a question to answer"))
	}

	// Serialize calls on the same MCP session so a follow-up does not race the
	// prior turn's daemon conversation.
	msess := s.lookupSession(sessionID)
	if msess != nil {
		msess.mu.Lock()
		defer msess.mu.Unlock()
	}

	// An ephemeral daemon session: its only message is a machine-written seed, so
	// it skips end-of-session memory curation. A session-keyed conversation key
	// keeps follow-up consults on the same daemon session id (context retained).
	convoKey := daemon.NewConversationKey()
	if msess != nil {
		convoKey = msess.convoKey
	}
	sess, _, err := s.dc.Sessions.GetOrCreate(ctx, s.Name(), convoKey, principal, daemon.SessionOptions{Ephemeral: true})
	if err != nil {
		return errorResponse(req.ID, codeInvalidRequest, "could not start consult session")
	}
	defer s.dc.Sessions.Release(sess)

	var reply replyCapture
	rep, err := sess.HandleConsult(ctx, question, daemon.RunCallbacks{OnMessage: reply.onMessage})
	if err != nil {
		s.audit("mcp_consult_failed", principal, map[string]any{"error": err.Error()})
		return result(req.ID, toolError("consult failed: "+err.Error()))
	}

	// The answer is the agent's prose. Fall back to the report summary on the rare
	// path where the agent finalized instead of answering in text.
	answer := reply.body()
	if answer == "" && rep != nil {
		answer = rep.Summary
	}

	// Audit the substantive answer before any placeholder, so "answered" reflects
	// whether Argus actually said something — not the filler the caller still needs
	// a non-empty content block for.
	s.audit("mcp_consult", principal, map[string]any{"answered": answer != ""})
	if answer == "" {
		answer = "Argus has nothing to add on this question."
	}
	return result(req.ID, consultToolResult(answer))
}

// consultToolResult renders the answer as an MCP tool result: the prose as a
// human-readable text block plus the structured payload the caller can act on.
func consultToolResult(answer string) toolCallResult {
	return toolCallResult{
		Content:           textContent(answer),
		StructuredContent: consultResult{Answer: answer},
	}
}

// replyCapture accumulates the agent's text turns during a consult run so the
// channel can return them as one answer. Tool-call turns carry no prose (empty
// Content) and are skipped; the answer is the model-role text it emits.
type replyCapture struct {
	mu   sync.Mutex
	msgs []string
}

// onMessage is the daemon.RunCallbacks.OnMessage hook: it keeps every non-empty
// model-role message in order.
func (r *replyCapture) onMessage(m provider.Message) {
	if m.Role != "model" {
		return
	}
	if c := strings.TrimSpace(m.Content); c != "" {
		r.mu.Lock()
		r.msgs = append(r.msgs, c)
		r.mu.Unlock()
	}
}

// body renders the captured turns as the answer, joining multiple prose turns.
func (r *replyCapture) body() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return strings.Join(r.msgs, "\n\n")
}
