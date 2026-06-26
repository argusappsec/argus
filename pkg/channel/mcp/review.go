package mcp

import (
	"context"
	"encoding/json"

	"github.com/redcarbon-dev/argus/pkg/auth"
	"github.com/redcarbon-dev/argus/pkg/daemon"
	"github.com/redcarbon-dev/argus/pkg/report"
	"github.com/redcarbon-dev/argus/pkg/snapshot"
)

// toolReview is the name of the hero capability (ADR 0011): an org-aware
// Snapshot review of caller-supplied code.
const toolReview = "review"

// reviewDescription is what the external AI reads to decide when to call
// review. It frames Argus as a colleague who applies the organization's own
// context, which is the boundary the MVP relies on (the surface advertises
// org-aware review; generic linting is the caller's own job — ADR 0011).
const reviewDescription = "Ask Argus — your organization's own security engineer — for a security review of code " +
	"you are working on, judged through YOUR organization's lens (its stack, conventions, infra, compliance " +
	"posture, and the false positives already accepted), not generic security advice. Hand over the changed " +
	"files from the developer's working tree as {path, content} pairs; Argus runs its real scanners and skills " +
	"over them and returns findings (severity, rule, file/line, snippet, remediation). Use this whenever the " +
	"developer asks \"is what I just wrote safe given how we build things?\" — not for textbook questions you " +
	"can already answer yourself."

// reviewToolDecl is the review tool's wire declaration for tools/list.
func reviewToolDecl() toolDecl {
	return toolDecl{
		Name:        toolReview,
		Description: reviewDescription,
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"files": map[string]any{
					"type":        "array",
					"description": "The files to review — typically the changed files from the developer's working tree.",
					"items": map[string]any{
						"type": "object",
						"properties": map[string]any{
							"path":    map[string]any{"type": "string", "description": "Repo-relative path, e.g. internal/auth/login.go"},
							"content": map[string]any{"type": "string", "description": "The full current content of the file."},
						},
						"required": []string{"path", "content"},
					},
				},
			},
			"required": []string{"files"},
		},
	}
}

// handleToolsList advertises the coarse capabilities (ADR 0011). The low-level
// scanners are deliberately absent — they stay inside Argus's own agent loop.
func (s *Server) handleToolsList(req rpcRequest) rpcResponse {
	return result(req.ID, toolsListResult{Tools: []toolDecl{reviewToolDecl()}})
}

// handleToolCall routes a tools/call to the named capability.
func (s *Server) handleToolCall(ctx context.Context, principal auth.Principal, req rpcRequest) rpcResponse {
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return errorResponse(req.ID, codeInvalidParams, "invalid tools/call params")
	}
	switch params.Name {
	case toolReview:
		return s.handleReview(ctx, principal, req, params.Arguments)
	default:
		return errorResponse(req.ID, codeMethodNotFound, "unknown tool: "+params.Name)
	}
}

// reviewFile is one caller-supplied file in a review call.
type reviewFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// reviewResult is the machine-readable payload returned to the caller: the
// findings in their normal report shape (so MCP findings match PR/Repo reviews)
// plus the agent's summary.
type reviewResult struct {
	Summary  string           `json:"summary"`
	Findings []report.Finding `json:"findings"`
}

// handleReview is the review capability: enforce RBAC at the tool layer,
// materialize the caller-supplied files into a Snapshot workspace, run the
// org-aware agent loop pointed at that workspace, and return the findings. The
// workspace is created and cleaned up within the call (one-shot Snapshot
// review); accumulation across follow-up calls is the collaborative slice.
func (s *Server) handleReview(ctx context.Context, principal auth.Principal, req rpcRequest, rawArgs json.RawMessage) rpcResponse {
	// RBAC at the tool layer so the channel cannot escalate a caller's role and
	// the refusal is uniform however the external AI phrases the request.
	if !canReview(principal.Role) {
		s.audit("mcp_review_denied", principal, map[string]any{"reason": "insufficient role"})
		return result(req.ID, toolError(errReviewDenied))
	}

	var args struct {
		Files []reviewFile `json:"files"`
	}
	if err := json.Unmarshal(rawArgs, &args); err != nil {
		return result(req.ID, toolError("invalid review arguments: "+err.Error()))
	}
	if len(args.Files) == 0 {
		return result(req.ID, toolError("review requires at least one file (path + content) to review"))
	}

	ws, err := snapshot.New()
	if err != nil {
		return errorResponse(req.ID, codeInvalidRequest, "could not create snapshot workspace")
	}
	defer func() { _ = ws.Close() }()

	files := make([]snapshot.File, len(args.Files))
	for i, f := range args.Files {
		files[i] = snapshot.File{Path: f.Path, Content: f.Content}
	}
	if err := ws.Add(files); err != nil {
		return result(req.ID, toolError("could not materialize files: "+err.Error()))
	}

	// A fresh, ephemeral session per review call (one-shot Snapshot review): its
	// only message is a machine-written seed over throwaway code, so it skips the
	// end-of-session memory curation. Keying the session by the MCP connection so
	// follow-up calls accumulate onto the same workspace is the collaborative slice.
	sess, _, err := s.dc.Sessions.GetOrCreate(ctx, s.Name(), daemon.NewConversationKey(), principal, daemon.SessionOptions{Ephemeral: true})
	if err != nil {
		return errorResponse(req.ID, codeInvalidRequest, "could not start review session")
	}
	defer s.dc.Sessions.Release(sess)

	rep, err := sess.HandleSnapshotReview(ctx, ws.Path(), daemon.RunCallbacks{})
	if err != nil {
		s.audit("mcp_review_failed", principal, map[string]any{"error": err.Error()})
		return result(req.ID, toolError("review failed: "+err.Error()))
	}

	s.audit("mcp_review", principal, map[string]any{
		"files":    len(args.Files),
		"findings": len(rep.Findings),
	})
	return result(req.ID, reviewToolResult(rep))
}

// canReview reports whether role may request a Snapshot review. Review is an
// analyst+ capability (the caller is typically a developer); viewers are
// read-only across channels and get consult, not review, in a later slice.
func canReview(role auth.Role) bool {
	return role == auth.RoleAdmin || role == auth.RoleAnalyst
}

// errReviewDenied is the tool-layer refusal a viewer's review attempt gets,
// phrased so the external AI relays it to the developer.
const errReviewDenied = "permission denied: requesting a security review requires the analyst or admin role; your role is read-only on this channel"

// reviewToolResult renders the report as an MCP tool result: a human-readable
// text block plus the structured findings the caller can act on.
func reviewToolResult(rep *report.Report) toolCallResult {
	rr := reviewResult{Summary: rep.Summary, Findings: rep.Findings}
	payload, err := json.MarshalIndent(rr, "", "  ")
	if err != nil {
		// report.Finding is plain data; marshal cannot realistically fail.
		return toolError("could not serialize findings: " + err.Error())
	}
	return toolCallResult{
		Content:           textContent(string(payload)),
		StructuredContent: rr,
	}
}

// toolError builds a CallToolResult carrying a tool-layer failure. It rides a
// successful JSON-RPC response (IsError set) so the calling AI surfaces the
// message rather than treating it as a transport error.
func toolError(msg string) toolCallResult {
	return toolCallResult{Content: textContent(msg), IsError: true}
}
