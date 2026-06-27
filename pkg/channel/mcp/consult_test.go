package mcp

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/redcarbon-dev/argus/pkg/auth"
	"github.com/redcarbon-dev/argus/pkg/provider"
)

// textAnswer scripts the agent to answer in prose (a text-only turn, no tool
// calls) — the natural shape of a consult reply.
func textAnswer(text string) []provider.Response {
	return []provider.Response{{Text: text}}
}

// readContextThenAnswer scripts the agent to consult an org CONTEXT document
// before answering, exercising the org-aware path of a consult turn.
func readContextThenAnswer(answer string) []provider.Response {
	return []provider.Response{
		{ToolCalls: []provider.ToolCall{{
			ID:   "ctx1",
			Name: "list_context",
			Args: map[string]any{},
		}}},
		{Text: answer},
	}
}

// structuredConsult parses the structured payload of a consult tool result.
func structuredConsult(t *testing.T, res toolCallResult) consultResult {
	t.Helper()
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var cr consultResult
	if err := json.Unmarshal(raw, &cr); err != nil {
		t.Fatalf("parse structured content: %v", err)
	}
	return cr
}

func TestToolsList_AdvertisesConsultWithSchema(t *testing.T) {
	s, _ := reviewServer(t, &scriptedProvider{responses: textAnswer("ok")}, auth.RoleAnalyst)
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

	var consult *toolDecl
	for i := range resp.Result.Tools {
		if resp.Result.Tools[i].Name == toolConsult {
			consult = &resp.Result.Tools[i]
		}
	}
	if consult == nil {
		t.Fatalf("tools/list must advertise consult, got %+v", resp.Result.Tools)
	}
	if consult.Description == "" {
		t.Error("consult must carry a description (the org-context boundary)")
	}
	props, _ := consult.InputSchema["properties"].(map[string]any)
	if _, ok := props["question"]; !ok {
		t.Errorf("consult schema must declare a question property: %+v", consult.InputSchema)
	}
}

func TestConsult_AnswersFromOrgContextWithNoTarget(t *testing.T) {
	// The agent consults an org document, then answers in prose: a consult turn
	// runs over the org's knowledge with no code target and returns the answer.
	s, auditPath := reviewServer(t, &scriptedProvider{responses: readContextThenAnswer("Log4Shell does not affect us; we are on logback.")}, auth.RoleAnalyst)
	body := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"consult","arguments":{"question":"Does Log4Shell affect us?"}}}`
	rec := post(t, s, testToken, body)
	if rec.Code != 200 {
		t.Fatalf("code = %d", rec.Code)
	}

	res := callResult(t, rec.Body.Bytes())
	if res.IsError {
		t.Fatalf("consult reported an error: %+v", res.Content)
	}

	cr := structuredConsult(t, res)
	if !strings.Contains(cr.Answer, "logback") {
		t.Errorf("answer = %q, want the org-grounded reply", cr.Answer)
	}
	// The human-readable block carries the prose answer too.
	if len(res.Content) == 0 || !strings.Contains(res.Content[0].Text, "logback") {
		t.Errorf("text content did not surface the answer: %+v", res.Content)
	}

	// The consult is attributed to the resolved Person in the audit log.
	e := findEvent(t, auditPath, "mcp_consult")
	if e == nil || e.Data["principal"] != "davide" {
		t.Errorf("expected an mcp_consult event attributed to davide, got %+v", e)
	}
}

func TestConsult_ViewerMayConsultReadOnly(t *testing.T) {
	// A viewer is read-only across channels but consult mutates nothing, so it is
	// allowed (unlike review, which a viewer is denied).
	s, auditPath := reviewServer(t, &scriptedProvider{responses: textAnswer("Our auth uses short-lived JWTs.")}, auth.RoleViewer)
	body := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"consult","arguments":{"question":"What are our auth conventions?"}}}`
	rec := post(t, s, testToken, body)
	res := callResult(t, rec.Body.Bytes())
	if res.IsError {
		t.Fatalf("a viewer's consult must be allowed (read-only), got error: %+v", res.Content)
	}
	cr := structuredConsult(t, res)
	if !strings.Contains(cr.Answer, "JWT") {
		t.Errorf("answer = %q, want the viewer's consult reply", cr.Answer)
	}
	if findEvent(t, auditPath, "mcp_consult") == nil {
		t.Error("a viewer's consult must record an mcp_consult event")
	}
}

func TestConsult_NoQuestionIsToolError(t *testing.T) {
	s, _ := reviewServer(t, &scriptedProvider{responses: textAnswer("ok")}, auth.RoleAnalyst)
	body := `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"consult","arguments":{"question":"  "}}}`
	rec := post(t, s, testToken, body)
	res := callResult(t, rec.Body.Bytes())
	if !res.IsError {
		t.Fatal("consult with no question must be a tool error")
	}
}
