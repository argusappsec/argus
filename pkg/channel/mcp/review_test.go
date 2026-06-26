package mcp

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
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
	if len(resp.Result.Tools) != 1 || resp.Result.Tools[0].Name != toolReview {
		t.Fatalf("tools = %+v, want exactly [review]", resp.Result.Tools)
	}
	tool := resp.Result.Tools[0]
	if tool.Description == "" {
		t.Error("review tool must carry a description (the org-aware boundary)")
	}
	// The scanners are never advertised as tools (ADR 0011).
	for _, name := range []string{"run_semgrep", "run_gitleaks", "run_osv_scanner"} {
		if tool.Name == name {
			t.Errorf("low-level scanner %q must not be exposed as an MCP tool", name)
		}
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
