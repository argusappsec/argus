package mcp

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/redcarbon-dev/argus/pkg/audit"
	"github.com/redcarbon-dev/argus/pkg/auth"
	"github.com/redcarbon-dev/argus/pkg/budget"
	"github.com/redcarbon-dev/argus/pkg/daemon"
	"github.com/redcarbon-dev/argus/pkg/provider"
	"github.com/redcarbon-dev/argus/pkg/report"
	"github.com/redcarbon-dev/argus/pkg/skill"
	"github.com/redcarbon-dev/argus/pkg/soul"
)

// scriptedProvider returns canned responses in order, repeating the last one.
type scriptedProvider struct {
	responses []provider.Response
	calls     int
}

func (f *scriptedProvider) Generate(_ context.Context, _ provider.Request) (provider.Response, error) {
	i := f.calls
	if i >= len(f.responses) {
		i = len(f.responses) - 1
	}
	f.calls++
	return f.responses[i], nil
}

// findingThenFinalize scripts the agent to record one finding and then finalize
// — the minimal complete one-shot review.
func findingThenFinalize() []provider.Response {
	return []provider.Response{
		{ToolCalls: []provider.ToolCall{{
			ID:   "c1",
			Name: "add_finding",
			Args: map[string]any{
				"severity":    "high",
				"rule_id":     "CWE-89",
				"file":        "login.go",
				"line":        float64(42),
				"snippet":     "db.Query(\"select * from users where name='\" + name + \"'\")",
				"title":       "SQL injection",
				"description": "User input is concatenated into a query.",
				"remediation": "Use parameterized queries.",
			},
		}}},
		{ToolCalls: []provider.ToolCall{{
			ID:   "c2",
			Name: "finalize_report",
			Args: map[string]any{"summary": "One SQL injection found."},
		}}},
	}
}

// reviewServer builds an MCP channel over a full DaemonContext wired to the
// given provider and a single Person with role on an MCP token == testToken.
func reviewServer(t *testing.T, prov provider.Provider, role auth.Role) (*Server, string) {
	t.Helper()
	home := t.TempDir()
	users := "persons:\n" +
		"  - id: davide\n" +
		"    role: " + string(role) + "\n" +
		"    mcp_tokens:\n" +
		"      - name: laptop\n" +
		"        sha256: " + auth.SHA256Hex(testToken) + "\n"
	usersPath := filepath.Join(home, "users.yaml")
	if err := os.WriteFile(usersPath, []byte(users), 0o600); err != nil {
		t.Fatal(err)
	}
	auditPath := filepath.Join(home, "audit.log.jsonl")
	aud, err := audit.NewLogger(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = aud.Close() })

	dc := &daemon.Context{
		Home:         home,
		DefaultModel: "gemini-2.5-flash",
		Pricing:      budget.Pricing{"gemini-2.5-flash": {InputUSDPer1M: 1, OutputUSDPer1M: 2}},
		Auth:         auth.NewResolver(usersPath),
		Audit:        aud,
		Reports:      report.NewWriter(filepath.Join(home, "reports")),
		Skills:       skill.NewCatalog(skill.Builtin(), filepath.Join(home, "skills")),
		NewProvider:  func(context.Context, string) (provider.Provider, error) { return prov, nil },
		LoadSoul:     func() (*soul.Soul, error) { return &soul.Soul{}, nil },
		LoadMemory:   func() (string, error) { return "", nil },
	}
	dc.Sessions = daemon.NewSessionManager(dc, 4)
	return NewServer(dc, Options{Addr: ":0"}), auditPath
}

// callResult parses a tools/call response into its CallToolResult.
func callResult(t *testing.T, rec []byte) toolCallResult {
	t.Helper()
	var resp struct {
		Result toolCallResult `json:"result"`
		Error  *rpcError      `json:"error"`
	}
	if err := json.Unmarshal(rec, &resp); err != nil {
		t.Fatalf("parse tools/call response: %v\nbody: %s", err, rec)
	}
	if resp.Error != nil {
		t.Fatalf("unexpected JSON-RPC error: %+v", resp.Error)
	}
	return resp.Result
}

func TestToolsList_AdvertisesReviewWithSchema(t *testing.T) {
	s, _ := reviewServer(t, &scriptedProvider{responses: findingThenFinalize()}, auth.RoleAnalyst)
	rec := post(t, s, testToken, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	if rec.Code != 200 {
		t.Fatalf("code = %d", rec.Code)
	}
	var resp struct {
		Result toolsListResult `json:"result"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse: %v", err)
	}
	var tool *toolDecl
	for i := range resp.Result.Tools {
		if resp.Result.Tools[i].Name == toolReview {
			tool = &resp.Result.Tools[i]
		}
		// The scanners are never advertised as tools (ADR 0011).
		for _, name := range []string{"run_semgrep", "run_gitleaks", "run_osv_scanner"} {
			if resp.Result.Tools[i].Name == name {
				t.Errorf("low-level scanner %q must not be exposed as an MCP tool", name)
			}
		}
	}
	if tool == nil {
		t.Fatalf("tools/list must advertise review, got %+v", resp.Result.Tools)
	}
	if tool.Description == "" {
		t.Error("review tool must carry a description (the org-aware boundary)")
	}
	props, _ := tool.InputSchema["properties"].(map[string]any)
	if _, ok := props["files"]; !ok {
		t.Errorf("input schema must declare a files property: %+v", tool.InputSchema)
	}
}

func TestReview_ReturnsFindingsThroughReportPipeline(t *testing.T) {
	s, auditPath := reviewServer(t, &scriptedProvider{responses: findingThenFinalize()}, auth.RoleAnalyst)
	body := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"review","arguments":{"files":[{"path":"login.go","content":"package main\n"}]}}}`
	rec := post(t, s, testToken, body)
	if rec.Code != 200 {
		t.Fatalf("code = %d", rec.Code)
	}

	res := callResult(t, rec.Body.Bytes())
	if res.IsError {
		t.Fatalf("review reported an error: %+v", res.Content)
	}

	// The structured payload carries the findings in their normal report shape.
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var rr reviewResult
	if err := json.Unmarshal(raw, &rr); err != nil {
		t.Fatalf("parse structured content: %v", err)
	}
	if rr.Summary != "One SQL injection found." {
		t.Errorf("summary = %q", rr.Summary)
	}
	if len(rr.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(rr.Findings))
	}
	f := rr.Findings[0]
	if f.Severity != "high" || f.RuleID != "CWE-89" || f.File != "login.go" || f.Line != 42 {
		t.Errorf("finding not carried through faithfully: %+v", f)
	}
	if f.ID == "" {
		t.Error("finding must get a content-derived ID from the report pipeline")
	}

	// The review is attributed to the resolved Person in the audit log.
	e := findEvent(t, auditPath, "mcp_review")
	if e == nil || e.Data["principal"] != "davide" {
		t.Errorf("expected an mcp_review event attributed to davide, got %+v", e)
	}
}

func TestReview_ViewerIsDeniedAtToolLayer(t *testing.T) {
	s, auditPath := reviewServer(t, &scriptedProvider{responses: findingThenFinalize()}, auth.RoleViewer)
	body := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"review","arguments":{"files":[{"path":"a.go","content":"x"}]}}}`
	rec := post(t, s, testToken, body)
	if rec.Code != 200 {
		t.Fatalf("code = %d", rec.Code)
	}
	res := callResult(t, rec.Body.Bytes())
	if !res.IsError {
		t.Fatal("a viewer's review must be denied (isError), not run")
	}
	if findEvent(t, auditPath, "mcp_review") != nil {
		t.Error("a denied review must not record an mcp_review (completed) event")
	}
	if findEvent(t, auditPath, "mcp_review_denied") == nil {
		t.Error("expected an mcp_review_denied audit event")
	}
}

func TestReview_NoFilesIsToolError(t *testing.T) {
	s, _ := reviewServer(t, &scriptedProvider{responses: findingThenFinalize()}, auth.RoleAnalyst)
	body := `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"review","arguments":{"files":[]}}}`
	rec := post(t, s, testToken, body)
	res := callResult(t, rec.Body.Bytes())
	if !res.IsError {
		t.Fatal("review with no files must be a tool error")
	}
}

// readFileCall scripts the agent to read one path via the file-scoped tool.
func readFileCall(path string) provider.Response {
	return provider.Response{ToolCalls: []provider.ToolCall{{
		ID:   "r1",
		Name: "read_file",
		Args: map[string]any{"path": path},
	}}}
}

// finalizeCall scripts the agent to finalize the report with a summary.
func finalizeCall(summary string) provider.Response {
	return provider.Response{ToolCalls: []provider.ToolCall{{
		ID:   "f1",
		Name: "finalize_report",
		Args: map[string]any{"summary": summary},
	}}}
}

// addFindingCall scripts the agent to record a finding on the given file.
func addFindingCall(file string) provider.Response {
	return provider.Response{ToolCalls: []provider.ToolCall{{
		ID:   "a1",
		Name: "add_finding",
		Args: map[string]any{
			"severity":    "high",
			"rule_id":     "BOLA-1",
			"file":        file,
			"line":        float64(10),
			"snippet":     "handler(w, r)",
			"title":       "Missing authorization check",
			"description": "The handler relies on middleware that does not authorize the actor.",
			"remediation": "Authorize the actor against the resource owner.",
		},
	}}}
}

// initSession runs the initialize handshake and returns the minted MCP session
// id the server handed back, so follow-up calls accumulate onto the same
// Snapshot workspace.
func initSession(t *testing.T, s *Server) string {
	t.Helper()
	rec := post(t, s, testToken, `{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	if rec.Code != 200 {
		t.Fatalf("initialize code = %d", rec.Code)
	}
	id := rec.Header().Get(sessionHeader)
	if id == "" {
		t.Fatal("initialize must mint an MCP session id (the workspace lives on it)")
	}
	return id
}

// postSession sends a JSON-RPC body carrying an MCP session id header.
func postSession(t *testing.T, s *Server, sessionID, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", endpointPath, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set(sessionHeader, sessionID)
	rec := httptest.NewRecorder()
	s.handle(rec, req)
	return rec
}

// structuredReview parses the structured payload of a review tool result.
func structuredReview(t *testing.T, res toolCallResult) reviewResult {
	t.Helper()
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var rr reviewResult
	if err := json.Unmarshal(raw, &rr); err != nil {
		t.Fatalf("parse structured content: %v", err)
	}
	return rr
}

func TestReview_ReturnsFilesNeededWhenContextMissing(t *testing.T) {
	// The agent reaches for a helper that was not supplied, then finalizes: the
	// missing path must come back as a structured files_needed request.
	prov := &scriptedProvider{responses: []provider.Response{
		readFileCall("internal/auth/middleware.go"),
		finalizeCall("Cannot judge without the middleware."),
	}}
	s, _ := reviewServer(t, prov, auth.RoleAnalyst)
	id := initSession(t, s)

	body := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"review","arguments":{"files":[{"path":"handler.go","content":"package main\n"}]}}}`
	res := callResult(t, postSession(t, s, id, body).Body.Bytes())
	if res.IsError {
		t.Fatalf("a files_needed result is collaborative, not an error: %+v", res.Content)
	}

	rr := structuredReview(t, res)
	if len(rr.FilesNeeded) != 1 || rr.FilesNeeded[0] != "internal/auth/middleware.go" {
		t.Fatalf("files_needed = %v, want [internal/auth/middleware.go]", rr.FilesNeeded)
	}
	// The human-readable block must lead with the request so the external AI acts.
	if len(res.Content) == 0 || !strings.Contains(res.Content[0].Text, "internal/auth/middleware.go") {
		t.Errorf("text content did not surface the files_needed request: %+v", res.Content)
	}
}

func TestReview_FollowUpAccumulatesAndCompletes(t *testing.T) {
	// Call 1 reaches for the middleware (absent) and finalizes → files_needed.
	// Call 2 supplies only the middleware; the agent reads it (now present),
	// records a finding, and finalizes → findings, no files_needed.
	prov := &scriptedProvider{responses: []provider.Response{
		readFileCall("internal/auth/middleware.go"), // run 1
		finalizeCall("Need the middleware to decide."),
		readFileCall("internal/auth/middleware.go"), // run 2 (now present)
		addFindingCall("handler.go"),
		finalizeCall("One missing authorization check."),
	}}
	s, _ := reviewServer(t, prov, auth.RoleAnalyst)
	id := initSession(t, s)

	call1 := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"review","arguments":{"files":[{"path":"handler.go","content":"package main\n"}]}}}`
	rr1 := structuredReview(t, callResult(t, postSession(t, s, id, call1).Body.Bytes()))
	if len(rr1.FilesNeeded) != 1 {
		t.Fatalf("call 1 files_needed = %v, want the middleware", rr1.FilesNeeded)
	}
	if len(rr1.Findings) != 0 {
		t.Errorf("call 1 should have no findings yet, got %d", len(rr1.Findings))
	}

	// The follow-up supplies ONLY the newly-fetched file — the handler is retained.
	call2 := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"review","arguments":{"files":[{"path":"internal/auth/middleware.go","content":"package auth\n"}]}}}`
	rr2 := structuredReview(t, callResult(t, postSession(t, s, id, call2).Body.Bytes()))
	if len(rr2.FilesNeeded) != 0 {
		t.Errorf("call 2 should need no more files, got %v", rr2.FilesNeeded)
	}
	if len(rr2.Findings) != 1 {
		t.Fatalf("call 2 findings = %d, want 1 (cross-file verdict after accumulation)", len(rr2.Findings))
	}
	if rr2.Findings[0].RuleID != "BOLA-1" {
		t.Errorf("finding = %+v, want the BOLA-1 verdict", rr2.Findings[0])
	}
}

func TestReview_FollowUpDoesNotResurfaceStaleMisses(t *testing.T) {
	// Call 1 reaches for two absent files; the AI supplies only one and the
	// follow-up run no longer needs the other. files_needed on call 2 must reflect
	// what THAT run still lacks — not the stale miss the AI deliberately skipped.
	prov := &scriptedProvider{responses: []provider.Response{
		readFileCall("a.go"), // run 1: both absent
		readFileCall("b.go"),
		finalizeCall("Need a.go and b.go."),
		readFileCall("a.go"), // run 2: a.go now present; b.go never touched
		finalizeCall("Reviewed with a.go."),
	}}
	s, _ := reviewServer(t, prov, auth.RoleAnalyst)
	id := initSession(t, s)

	call1 := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"review","arguments":{"files":[{"path":"seed.go","content":"package main\n"}]}}}`
	rr1 := structuredReview(t, callResult(t, postSession(t, s, id, call1).Body.Bytes()))
	if len(rr1.FilesNeeded) != 2 {
		t.Fatalf("call 1 files_needed = %v, want both a.go and b.go", rr1.FilesNeeded)
	}

	call2 := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"review","arguments":{"files":[{"path":"a.go","content":"package main\n"}]}}}`
	rr2 := structuredReview(t, callResult(t, postSession(t, s, id, call2).Body.Bytes()))
	if len(rr2.FilesNeeded) != 0 {
		t.Errorf("call 2 must not re-request the stale b.go, got %v", rr2.FilesNeeded)
	}
}

func TestReview_DeleteClosesSession(t *testing.T) {
	prov := &scriptedProvider{responses: findingThenFinalize()}
	s, _ := reviewServer(t, prov, auth.RoleAnalyst)
	id := initSession(t, s)
	if s.lookupSession(id) == nil {
		t.Fatal("session should be live after initialize")
	}

	req := httptest.NewRequest("DELETE", endpointPath, nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set(sessionHeader, id)
	rec := httptest.NewRecorder()
	s.handle(rec, req)
	if rec.Code != 204 {
		t.Fatalf("DELETE code = %d, want 204", rec.Code)
	}
	if s.lookupSession(id) != nil {
		t.Error("session must be gone after DELETE (workspace cleaned up)")
	}
}

func TestToolCall_UnknownToolIsMethodNotFound(t *testing.T) {
	s, _ := reviewServer(t, &scriptedProvider{responses: findingThenFinalize()}, auth.RoleAnalyst)
	body := `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"run_semgrep","arguments":{}}}`
	rec := post(t, s, testToken, body)
	var resp rpcResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Error == nil || resp.Error.Code != codeMethodNotFound {
		t.Fatalf("error = %+v, want method-not-found (the scanners are not callable tools)", resp.Error)
	}
}
