package mcp

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/argusappsec/argus/pkg/auth"
	"github.com/argusappsec/argus/pkg/daemon"
	"github.com/argusappsec/argus/pkg/report"
	"github.com/argusappsec/argus/pkg/snapshot"
)

// toolReview is the name of the hero capability (ADR 0011): an org-aware
// Snapshot review of caller-supplied code.
const toolReview = "review"

// reviewDescription is what the external AI reads to decide when to call
// review. It frames Argus as a colleague who applies the organization's own
// context, which is the boundary the MVP relies on (the surface advertises
// org-aware review; generic linting is the caller's own job — ADR 0011). The
// one tool accepts two mutually exclusive targets: caller-supplied files (a
// Snapshot review) or a codehost repo reference (a Repo review — ADR 0016).
const reviewDescription = "Ask Argus — your organization's own security engineer — for a security review of code, " +
	"judged through YOUR organization's lens (its stack, conventions, infra, compliance posture, and the false " +
	"positives already accepted), not generic security advice. Argus runs its real scanners and skills and " +
	"returns findings (severity, rule, file/line, snippet, remediation). Give it EITHER `files` — the changed " +
	"files from the developer's working tree as {path, content} pairs, for a Snapshot review — OR `repo` + `ref` " +
	"to review a whole repository the App can access (private repos included). Use `files` whenever the developer " +
	"asks \"is what I just wrote safe given how we build things?\"; use `repo` to review code you do not hold " +
	"locally. Not for textbook questions you can already answer yourself."

// reviewToolDecl is the review tool's wire declaration for tools/list. The
// schema advertises both target forms; mutual exclusion is enforced at the tool
// layer (JSON Schema cannot express "exactly one of these") and reported as a
// clear validation error.
func reviewToolDecl() toolDecl {
	return toolDecl{
		Name:        toolReview,
		Description: reviewDescription,
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"files": map[string]any{
					"type":        "array",
					"description": "Snapshot target: the files to review as {path, content} pairs — typically the changed files from the developer's working tree. Mutually exclusive with repo/ref.",
					"items": map[string]any{
						"type": "object",
						"properties": map[string]any{
							"path":    map[string]any{"type": "string", "description": "Repo-relative path, e.g. internal/auth/login.go"},
							"content": map[string]any{"type": "string", "description": "The full current content of the file."},
						},
						"required": []string{"path", "content"},
					},
				},
				"repo": map[string]any{
					"type":        "string",
					"description": "Repo target: a codehost repository URL (https://github.com/owner/repo) or short form (github.com/owner/repo) to review in full. Mutually exclusive with files.",
				},
				"ref": map[string]any{
					"type":        "string",
					"description": "Optional branch, tag, or commit SHA for the repo target. Default: the repository's default branch.",
				},
			},
		},
	}
}

// handleToolsList advertises the coarse capabilities (ADR 0011). The low-level
// scanners are deliberately absent — they stay inside Argus's own agent loop.
func (s *Server) handleToolsList(req rpcRequest) rpcResponse {
	return result(req.ID, toolsListResult{Tools: []toolDecl{reviewToolDecl(), consultToolDecl()}})
}

// handleToolCall routes a tools/call to the named capability. sessionID is the
// caller's MCP session (empty for a sessionless one-shot client), threaded to
// review so follow-up calls accumulate onto the same Snapshot workspace.
func (s *Server) handleToolCall(ctx context.Context, principal auth.Principal, sessionID string, req rpcRequest) rpcResponse {
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return errorResponse(req.ID, codeInvalidParams, "invalid tools/call params")
	}
	switch params.Name {
	case toolReview:
		return s.handleReview(ctx, principal, sessionID, req, params.Arguments)
	case toolConsult:
		return s.handleConsult(ctx, principal, sessionID, req, params.Arguments)
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
// plus the agent's summary. FilesNeeded carries the collaborative request: the
// paths the agent reached for that the snapshot did not hold. When non-empty the
// external AI should fetch them from the working tree and call review again on
// the same MCP session, supplying only those files (the workspace accumulates).
type reviewResult struct {
	Summary     string           `json:"summary"`
	Findings    []report.Finding `json:"findings"`
	FilesNeeded []string         `json:"files_needed,omitempty"`
}

// handleReview is the review capability: enforce RBAC at the tool layer, then
// route to the target the caller named — caller-supplied files (a Snapshot
// review) or a codehost repo reference (a Repo review, ADR 0016). The two forms
// are mutually exclusive; supplying both or neither is a validation error.
func (s *Server) handleReview(ctx context.Context, principal auth.Principal, sessionID string, req rpcRequest, rawArgs json.RawMessage) rpcResponse {
	// RBAC at the tool layer so the channel cannot escalate a caller's role and
	// the refusal is uniform however the external AI phrases the request.
	if !canReview(principal.Role) {
		s.audit("mcp_review_denied", principal, map[string]any{"reason": "insufficient role"})
		return result(req.ID, toolError(errReviewDenied))
	}

	var args struct {
		Files []reviewFile `json:"files"`
		Repo  string       `json:"repo"`
		Ref   string       `json:"ref"`
	}
	if err := json.Unmarshal(rawArgs, &args); err != nil {
		return result(req.ID, toolError("invalid review arguments: "+err.Error()))
	}

	// Exactly one target form. The two are mutually exclusive (a Snapshot review
	// materializes caller content; a Repo review clones a real checkout), so the
	// caller must pick one — an ambiguous request is refused rather than guessed.
	hasSnapshot := len(args.Files) > 0
	repoRef := strings.TrimSpace(args.Repo)
	hasRepo := repoRef != ""
	switch {
	case hasSnapshot && hasRepo:
		return result(req.ID, toolError("review accepts either files (a snapshot) or repo (a repository), not both — pick one target"))
	case !hasSnapshot && !hasRepo:
		return result(req.ID, toolError("review requires a target: either files (path + content pairs) to review, or a repo reference to review in full"))
	case hasRepo:
		return s.handleRepoReview(ctx, principal, req, repoRef, strings.TrimSpace(args.Ref))
	default:
		return s.handleSnapshotReview(ctx, principal, sessionID, req, args.Files)
	}
}

// handleSnapshotReview materializes the caller-supplied files into a Snapshot
// workspace, runs the org-aware agent loop pointed at that workspace, and
// returns either findings or a structured files_needed request (the
// collaborative Snapshot review, ADR 0011).
//
// When the caller carries an MCP session, the workspace lives on that session so
// a follow-up review accumulates the newly supplied files onto it (no resend)
// and a previously-missing path is satisfied. A sessionless one-shot client gets
// a workspace created and cleaned up within the call.
func (s *Server) handleSnapshotReview(ctx context.Context, principal auth.Principal, sessionID string, req rpcRequest, reviewFiles []reviewFile) rpcResponse {
	// The workspace is session-scoped when the caller has an MCP session, so
	// follow-up calls accumulate; otherwise it is one-shot. Serialize calls on the
	// same session so a follow-up does not race the prior call's workspace/run.
	msess := s.lookupSession(sessionID)
	if msess != nil {
		msess.mu.Lock()
		defer msess.mu.Unlock()
	}

	ws, oneShot, err := s.workspaceFor(msess)
	if err != nil {
		return errorResponse(req.ID, codeInvalidRequest, "could not create snapshot workspace")
	}
	if oneShot {
		defer func() { _ = ws.Close() }()
	}

	files := make([]snapshot.File, len(reviewFiles))
	for i, f := range reviewFiles {
		files[i] = snapshot.File{Path: f.Path, Content: f.Content}
	}
	if err := ws.Add(files); err != nil {
		return result(req.ID, toolError("could not materialize files: "+err.Error()))
	}
	// Start each run from a clean miss slate: files_needed must reflect what this
	// run still lacks, not paths an earlier call reached for and the AI chose not
	// to supply (it accumulates files, not stale requests).
	ws.ResetMisses()

	// An ephemeral daemon session per review call: its only message is a
	// machine-written seed over throwaway code, so it skips the end-of-session
	// memory curation. A session-keyed conversation key keeps follow-up calls on
	// the same daemon session id (the accumulated workspace carries the files).
	convoKey := daemon.NewConversationKey()
	if msess != nil {
		convoKey = msess.convoKey
	}
	sess, _, err := s.dc.Sessions.GetOrCreate(ctx, s.Name(), convoKey, principal, daemon.SessionOptions{Ephemeral: true})
	if err != nil {
		return errorResponse(req.ID, codeInvalidRequest, "could not start review session")
	}
	defer s.dc.Sessions.Release(sess)

	rep, err := sess.HandleSnapshotReview(ctx, ws.Path(), ws, daemon.RunCallbacks{})
	if err != nil {
		s.audit("mcp_review_failed", principal, map[string]any{"error": err.Error()})
		return result(req.ID, toolError("review failed: "+err.Error()))
	}

	missing := ws.Missing()
	s.audit("mcp_review", principal, map[string]any{
		"files":        len(reviewFiles),
		"findings":     len(rep.Findings),
		"files_needed": len(missing),
	})
	return result(req.ID, reviewToolResult(rep, missing))
}

// handleRepoReview clones the named codehost repository through the shared
// authenticated codehost client and runs a full-tree Repo review (ADR 0016).
// The dispatch is deterministic (not model-mediated): the target is parsed and
// cloned here, then handed straight to the Session's review spine. A repo target
// requires a configured codehost of the matching host; with none it fails with a
// clear error naming what the operator must enable. Unlike a Snapshot review the
// checkout is complete, so there is no files_needed accumulation and no MCP
// session workspace to carry across calls.
func (s *Server) handleRepoReview(ctx context.Context, principal auth.Principal, req rpcRequest, repoRef, ref string) rpcResponse {
	host := s.dc.CodeHost
	if host == nil {
		return result(req.ID, toolError("review of a repository requires a configured codehost — add a github entry under `codehosts:` in argus.yaml, or supply the changed files directly for a snapshot review"))
	}

	repo, err := host.ParseURL(repoRef)
	if err != nil {
		return result(req.ID, toolError("could not parse repo reference: "+err.Error()))
	}

	co, err := host.Clone(ctx, repo, ref)
	if err != nil {
		s.audit("mcp_review_failed", principal, map[string]any{"repo": repo.FullName, "error": err.Error()})
		return result(req.ID, toolError("could not clone repository: "+err.Error()))
	}

	// A repo review is one-shot and stateless across MCP sessions (the full tree
	// is present), so an ephemeral daemon session keyed to this repo checkout is
	// enough — no workspace accumulation to preserve.
	sess, _, err := s.dc.Sessions.GetOrCreate(ctx, s.Name(), daemon.NewConversationKey(), principal, daemon.SessionOptions{Ephemeral: true})
	if err != nil {
		return errorResponse(req.ID, codeInvalidRequest, "could not start review session")
	}
	defer s.dc.Sessions.Release(sess)

	rep, _, err := sess.HandleRepoReview(ctx, daemon.RepoReviewTarget{
		Repo: repo.FullName,
		SHA:  co.SHA,
		Path: co.Path,
	}, daemon.RunCallbacks{})
	if err != nil {
		s.audit("mcp_review_failed", principal, map[string]any{"repo": repo.FullName, "error": err.Error()})
		return result(req.ID, toolError("review failed: "+err.Error()))
	}

	s.audit("mcp_review", principal, map[string]any{
		"repo":     repo.FullName,
		"ref":      co.SHA,
		"findings": len(rep.Findings),
	})
	return result(req.ID, reviewToolResult(rep, nil))
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
// text block plus the structured findings the caller can act on. When the run
// recorded misses, the structured result carries files_needed and the text leads
// with the request so the external AI fetches them and calls review again.
func reviewToolResult(rep *report.Report, missing []string) toolCallResult {
	rr := reviewResult{Summary: rep.Summary, Findings: rep.Findings, FilesNeeded: missing}
	payload, err := json.MarshalIndent(rr, "", "  ")
	if err != nil {
		// report.Finding is plain data; marshal cannot realistically fail.
		return toolError("could not serialize findings: " + err.Error())
	}
	text := string(payload)
	if len(missing) > 0 {
		text = filesNeededNote(missing) + "\n\n" + text
	}
	return toolCallResult{
		Content:           textContent(text),
		StructuredContent: rr,
	}
}

// filesNeededNote is the human/AI-facing instruction that leads a review result
// when Argus reached for files the snapshot did not hold. It tells the external
// AI exactly what to do: fetch these paths and call review again on the same
// session with just those files (the workspace accumulates).
func filesNeededNote(missing []string) string {
	var b strings.Builder
	b.WriteString("Argus needs more of the call chain to finish this review. Fetch these files from the ")
	b.WriteString("developer's working tree and call review again on this same MCP session, supplying just ")
	b.WriteString("these additional files (the ones already sent are retained):\n")
	for _, p := range missing {
		b.WriteString("  - ")
		b.WriteString(p)
		b.WriteByte('\n')
	}
	return b.String()
}

// toolError builds a CallToolResult carrying a tool-layer failure. It rides a
// successful JSON-RPC response (IsError set) so the calling AI surfaces the
// message rather than treating it as a transport error.
func toolError(msg string) toolCallResult {
	return toolCallResult{Content: textContent(msg), IsError: true}
}
