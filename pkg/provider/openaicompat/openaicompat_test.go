package openaicompat_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/argusappsec/argus/pkg/provider"
	"github.com/argusappsec/argus/pkg/provider/openaicompat"
)

// recorder captures the request Argus actually put on the wire. Tests assert
// on this and on the returned provider.Response — never on how either was
// built.
type recorder struct {
	mu     sync.Mutex
	method string
	path   string
	query  string
	header http.Header
	body   []byte
}

func (r *recorder) snapshot() (method, path string, header http.Header, body []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.method, r.path, r.header, r.body
}

func (r *recorder) rawQuery() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.query
}

// raw decodes the request body as a bare map, so a test can assert that a
// field is absent from the JSON rather than merely zero.
func (r *recorder) raw(t *testing.T) map[string]any {
	t.Helper()
	_, _, _, body := r.snapshot()
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("request body is not JSON: %v (%s)", err, body)
	}
	return m
}

// wireRequest is the chat-completions request as a compatible server sees it.
type wireRequest struct {
	Model    string        `json:"model"`
	Messages []wireMessage `json:"messages"`
	Tools    []wireTool    `json:"tools"`
}

type wireMessage struct {
	Role       string         `json:"role"`
	Content    string         `json:"content"`
	ToolCallID string         `json:"tool_call_id"`
	ToolCalls  []wireToolCall `json:"tool_calls"`
}

type wireToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type wireTool struct {
	Type     string `json:"type"`
	Function struct {
		Name        string         `json:"name"`
		Description string         `json:"description"`
		Parameters  map[string]any `json:"parameters"`
	} `json:"function"`
}

func (r *recorder) request(t *testing.T) wireRequest {
	t.Helper()
	_, _, _, body := r.snapshot()
	var req wireRequest
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("decode request: %v (%s)", err, body)
	}
	return req
}

// stubServer stands in for an OpenAI-compatible endpoint, replying with a
// fixed status and raw JSON body so tests can hand back exactly the bytes a
// sloppy server would.
func stubServer(t *testing.T, status int, body string) (*httptest.Server, *recorder) {
	t.Helper()
	rec := &recorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
		}
		rec.mu.Lock()
		rec.method, rec.path, rec.query = r.Method, r.URL.Path, r.URL.RawQuery
		rec.header, rec.body = r.Header.Clone(), b
		rec.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, rec
}

// A compatible client is only useful where Argus expects an LLM provider.
var _ provider.Provider = (*openaicompat.Client)(nil)

// newClient builds a client pointed at srv, failing the test if construction
// does.
func newClient(t *testing.T, cfg openaicompat.Config) *openaicompat.Client {
	t.Helper()
	c, err := openaicompat.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestGenerate_CarriesModelAndMessagesAndReturnsTextAndUsage(t *testing.T) {
	srv, rec := stubServer(t, http.StatusOK, `{
	  "id": "chatcmpl-1",
	  "choices": [
	    {"index": 0, "message": {"role": "assistant", "content": "all clear"}, "finish_reason": "stop"}
	  ],
	  "usage": {"prompt_tokens": 11, "completion_tokens": 3, "total_tokens": 14}
	}`)

	c := newClient(t, openaicompat.Config{
		APIKey:     "sk-test",
		BaseURL:    srv.URL,
		Model:      "test-model",
		HTTPClient: srv.Client(),
	})

	resp, err := c.Generate(context.Background(), provider.Request{
		System:   "you are Argus",
		Messages: []provider.Message{{Role: "user", Content: "review this repo"}},
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	method, path, header, _ := rec.snapshot()
	if method != http.MethodPost {
		t.Errorf("method = %q, want POST", method)
	}
	if path != "/chat/completions" {
		t.Errorf("path = %q, want /chat/completions", path)
	}
	if got := header.Get("Authorization"); got != "Bearer sk-test" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer sk-test")
	}
	if got := header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}

	got := rec.request(t)
	if got.Model != "test-model" {
		t.Errorf("model = %q, want test-model", got.Model)
	}
	// No tools were declared, so the field must not appear at all: some servers
	// reject an empty tools array.
	if v, ok := rec.raw(t)["tools"]; ok {
		t.Errorf("tools present (%v), want absent", v)
	}
	want := []wireMessage{
		{Role: "system", Content: "you are Argus"},
		{Role: "user", Content: "review this repo"},
	}
	if len(got.Messages) != len(want) {
		t.Fatalf("messages = %+v, want %+v", got.Messages, want)
	}
	for i := range want {
		if got.Messages[i].Role != want[i].Role || got.Messages[i].Content != want[i].Content {
			t.Errorf("message %d = %+v, want %+v", i, got.Messages[i], want[i])
		}
	}

	if resp.Text != "all clear" {
		t.Errorf("text = %q, want %q", resp.Text, "all clear")
	}
	if resp.Usage != (provider.Usage{InputTokens: 11, OutputTokens: 3}) {
		t.Errorf("usage = %+v, want {11 3}", resp.Usage)
	}
	if len(resp.ToolCalls) != 0 {
		t.Errorf("tool calls = %+v, want none", resp.ToolCalls)
	}
}

// A Provider without an output ceiling must not put one on the wire: a zero
// value would cap generation at nothing.
func TestGenerate_OmitsOutputCeilingUnlessConfigured(t *testing.T) {
	srv, rec := stubServer(t, http.StatusOK, `{"choices":[{"message":{"content":"ok"}}]}`)
	c := newClient(t, openaicompat.Config{BaseURL: srv.URL, Model: "m", HTTPClient: srv.Client()})

	if _, err := c.Generate(context.Background(), provider.Request{
		Messages: []provider.Message{{Role: "user", Content: "hi"}},
	}); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	body := rec.raw(t)
	for _, field := range []string{"max_tokens", "max_completion_tokens"} {
		if v, ok := body[field]; ok {
			t.Errorf("%s present (%v), want absent", field, v)
		}
	}
}

func TestGenerate_SendsOutputCeilingWhenConfigured(t *testing.T) {
	srv, rec := stubServer(t, http.StatusOK, `{"choices":[{"message":{"content":"ok"}}]}`)
	c := newClient(t, openaicompat.Config{
		BaseURL:         srv.URL,
		Model:           "m",
		MaxOutputTokens: 4096,
		HTTPClient:      srv.Client(),
	})

	if _, err := c.Generate(context.Background(), provider.Request{
		Messages: []provider.Message{{Role: "user", Content: "hi"}},
	}); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if got, want := rec.raw(t)["max_tokens"], float64(4096); got != want {
		t.Errorf("max_tokens = %v, want %v", got, want)
	}
}

// A local runtime needs no key, and sending an empty bearer token is worse
// than sending nothing: some servers reject a malformed header outright.
func TestGenerate_OmitsAuthorizationWhenNoKey(t *testing.T) {
	srv, rec := stubServer(t, http.StatusOK, `{"choices":[{"message":{"content":"ok"}}]}`)
	c := newClient(t, openaicompat.Config{BaseURL: srv.URL, Model: "m", HTTPClient: srv.Client()})

	if _, err := c.Generate(context.Background(), provider.Request{
		Messages: []provider.Message{{Role: "user", Content: "hi"}},
	}); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	_, _, header, _ := rec.snapshot()
	if _, ok := header["Authorization"]; ok {
		t.Errorf("Authorization header present (%q), want absent", header.Get("Authorization"))
	}
}

func TestGenerate_CarriesToolDeclarations(t *testing.T) {
	srv, rec := stubServer(t, http.StatusOK, `{"choices":[{"message":{"content":"ok"}}]}`)
	c := newClient(t, openaicompat.Config{BaseURL: srv.URL, Model: "m", HTTPClient: srv.Client()})

	schema := map[string]any{
		"type":       "object",
		"properties": map[string]any{"path": map[string]any{"type": "string"}},
		"required":   []any{"path"},
	}
	if _, err := c.Generate(context.Background(), provider.Request{
		Messages: []provider.Message{{Role: "user", Content: "read a file"}},
		Tools: []provider.ToolDecl{
			{Name: "read_file", Description: "Read a file from the checkout", Schema: schema},
			{Name: "finalize_report", Description: "Finalize the Report"},
		},
	}); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	got := rec.request(t)
	if len(got.Tools) != 2 {
		t.Fatalf("tools = %+v, want 2", got.Tools)
	}
	if got.Tools[0].Type != "function" {
		t.Errorf("tool type = %q, want function", got.Tools[0].Type)
	}
	if got.Tools[0].Function.Name != "read_file" {
		t.Errorf("tool name = %q, want read_file", got.Tools[0].Function.Name)
	}
	if got.Tools[0].Function.Description != "Read a file from the checkout" {
		t.Errorf("tool description = %q", got.Tools[0].Function.Description)
	}
	// The declared JSON schema is passed through unchanged.
	if diff := jsonDiff(t, schema, got.Tools[0].Function.Parameters); diff != "" {
		t.Errorf("tool parameters mangled: %s", diff)
	}
	if got.Tools[1].Function.Name != "finalize_report" {
		t.Errorf("second tool = %+v", got.Tools[1])
	}
}

func TestGenerate_ReturnsMultipleToolCalls(t *testing.T) {
	srv, _ := stubServer(t, http.StatusOK, `{
	  "choices": [{"message": {"role": "assistant", "content": null, "tool_calls": [
	    {"id": "call_a", "type": "function", "function": {"name": "read_file", "arguments": "{\"path\":\"main.go\"}"}},
	    {"id": "call_b", "type": "function", "function": {"name": "run_scanner", "arguments": "{\"name\":\"semgrep\",\"deep\":true}"}}
	  ]}, "finish_reason": "tool_calls"}]
	}`)
	c := newClient(t, openaicompat.Config{BaseURL: srv.URL, Model: "m", HTTPClient: srv.Client()})

	resp, err := c.Generate(context.Background(), provider.Request{
		Messages: []provider.Message{{Role: "user", Content: "go"}},
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(resp.ToolCalls) != 2 {
		t.Fatalf("tool calls = %+v, want 2", resp.ToolCalls)
	}
	first, second := resp.ToolCalls[0], resp.ToolCalls[1]
	if first.ID != "call_a" || first.Name != "read_file" {
		t.Errorf("first call = %+v", first)
	}
	if got, want := first.Args["path"], "main.go"; got != want {
		t.Errorf("first args = %v, want path=%q", first.Args, want)
	}
	if second.ID != "call_b" || second.Name != "run_scanner" {
		t.Errorf("second call = %+v", second)
	}
	if got := second.Args["deep"]; got != true {
		t.Errorf("second args = %v, want deep=true", second.Args)
	}
}

// Some models narrate and call a tool in the same message. Both halves survive.
func TestGenerate_KeepsContentAlongsideToolCalls(t *testing.T) {
	srv, _ := stubServer(t, http.StatusOK, `{
	  "choices": [{"message": {"content": "Let me look at that file.", "tool_calls": [
	    {"id": "call_1", "type": "function", "function": {"name": "read_file", "arguments": "{}"}}
	  ]}}]
	}`)
	c := newClient(t, openaicompat.Config{BaseURL: srv.URL, Model: "m", HTTPClient: srv.Client()})

	resp, err := c.Generate(context.Background(), provider.Request{
		Messages: []provider.Message{{Role: "user", Content: "go"}},
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if resp.Text != "Let me look at that file." {
		t.Errorf("text = %q, want the narration kept", resp.Text)
	}
	if len(resp.ToolCalls) != 1 || resp.ToolCalls[0].Name != "read_file" {
		t.Errorf("tool calls = %+v, want one read_file", resp.ToolCalls)
	}
}

// The protocol correlates a tool result to its call by id, unlike Gemini which
// correlates by function name. A conversation that has already been through a
// tool round-trip must go back on the wire with that correlation intact.
func TestGenerate_MapsRolesAndCorrelatesToolResultsByID(t *testing.T) {
	srv, rec := stubServer(t, http.StatusOK, `{"choices":[{"message":{"content":"done"}}]}`)
	c := newClient(t, openaicompat.Config{BaseURL: srv.URL, Model: "m", HTTPClient: srv.Client()})

	if _, err := c.Generate(context.Background(), provider.Request{
		Messages: []provider.Message{
			{Role: "user", Content: "review this repo"},
			{Role: "model", Content: "Checking two files.", ToolCalls: []provider.ToolCall{
				{ID: "call_1", Name: "read_file", Args: map[string]any{"path": "main.go"}},
				{ID: "call_2", Name: "read_file", Args: map[string]any{"path": "go.mod"}},
			}},
			{Role: "tool", ToolResults: []provider.ToolResult{
				{CallID: "call_1", Name: "read_file", Output: "package main"},
				{CallID: "call_2", Name: "read_file", Output: "no such file", IsError: true},
			}},
		},
	}); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	msgs := rec.request(t).Messages
	if len(msgs) != 4 {
		t.Fatalf("messages = %+v, want 4 (user, assistant, tool, tool)", msgs)
	}

	if msgs[0].Role != "user" || msgs[0].Content != "review this repo" {
		t.Errorf("message 0 = %+v", msgs[0])
	}

	// The model turn becomes an assistant message carrying its tool calls.
	assistant := msgs[1]
	if assistant.Role != "assistant" {
		t.Errorf("role = %q, want assistant", assistant.Role)
	}
	if assistant.Content != "Checking two files." {
		t.Errorf("assistant content = %q", assistant.Content)
	}
	if len(assistant.ToolCalls) != 2 {
		t.Fatalf("assistant tool calls = %+v, want 2", assistant.ToolCalls)
	}
	if assistant.ToolCalls[0].ID != "call_1" || assistant.ToolCalls[0].Type != "function" {
		t.Errorf("first call = %+v", assistant.ToolCalls[0])
	}
	if assistant.ToolCalls[0].Function.Name != "read_file" {
		t.Errorf("first call name = %q", assistant.ToolCalls[0].Function.Name)
	}
	// Arguments travel as a JSON-encoded string, not as an object.
	var args map[string]any
	if err := json.Unmarshal([]byte(assistant.ToolCalls[0].Function.Arguments), &args); err != nil {
		t.Fatalf("arguments %q is not a JSON string of an object: %v", assistant.ToolCalls[0].Function.Arguments, err)
	}
	if args["path"] != "main.go" {
		t.Errorf("arguments = %v, want path=main.go", args)
	}
	if assistant.ToolCalls[1].ID != "call_2" {
		t.Errorf("second call = %+v", assistant.ToolCalls[1])
	}

	// Each result becomes its own tool message, keyed by the call id.
	for i, want := range []struct{ id, contains string }{
		{"call_1", "package main"},
		{"call_2", "no such file"},
	} {
		m := msgs[2+i]
		if m.Role != "tool" {
			t.Errorf("message %d role = %q, want tool", 2+i, m.Role)
		}
		if m.ToolCallID != want.id {
			t.Errorf("message %d tool_call_id = %q, want %q", 2+i, m.ToolCallID, want.id)
		}
		if !strings.Contains(m.Content, want.contains) {
			t.Errorf("message %d content = %q, want it to contain %q", 2+i, m.Content, want.contains)
		}
	}
	// A failed tool is marked as such: the protocol has no error flag on a tool
	// message, so the signal has to live in the content.
	if !strings.Contains(strings.ToLower(msgs[3].Content), "error") {
		t.Errorf("failed tool result content = %q, want an error marker", msgs[3].Content)
	}
	if strings.Contains(strings.ToLower(msgs[2].Content), "error") {
		t.Errorf("successful tool result content = %q, want no error marker", msgs[2].Content)
	}
}

// --- Tolerance ---------------------------------------------------------------
//
// Argus talks to servers that are only approximately OpenAI. Each case below is
// a real deviation a compatible server ships today, and accepting it is the
// point of hand-writing this client rather than using a strict SDK.

// answering runs one turn against a server that always replies with body, the
// shape every tolerance case needs.
func answering(t *testing.T, body string) (provider.Response, error) {
	t.Helper()
	srv, _ := stubServer(t, http.StatusOK, body)
	c := newClient(t, openaicompat.Config{BaseURL: srv.URL, Model: "m", HTTPClient: srv.Client()})
	return c.Generate(context.Background(), provider.Request{
		Messages: []provider.Message{{Role: "user", Content: "hi"}},
	})
}

// A server that reports no usage is not an error: token counts are a readout,
// not a control.
func TestGenerate_ToleratesAbsentUsage(t *testing.T) {
	resp, err := answering(t, `{"choices":[{"message":{"content":"fine"}}]}`)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if resp.Usage != (provider.Usage{}) {
		t.Errorf("usage = %+v, want zero", resp.Usage)
	}
	if resp.Text != "fine" {
		t.Errorf("text = %q, want fine", resp.Text)
	}
}

// Argus never acts on finish_reason, so an invented one must pass through
// unnoticed.
func TestGenerate_ToleratesUnknownFinishReason(t *testing.T) {
	resp, err := answering(t, `{
	  "choices":[{"message":{"content":"stopped early"},"finish_reason":"eos_token_reached"}],
	  "usage":{"prompt_tokens":4,"completion_tokens":2}
	}`)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if resp.Text != "stopped early" {
		t.Errorf("text = %q", resp.Text)
	}
}

// A server that omits tool-call ids would otherwise break every turn with more
// than one call. Argus synthesizes usable, distinct ids instead, and the ids it
// hands out are the ids it puts back on the wire — which is what keeps the
// assistant tool_calls and the tool messages paired.
func TestGenerate_ToleratesEmptyToolCallIDs(t *testing.T) {
	body := `{"choices":[{"message":{"tool_calls":[
	  {"id":"","type":"function","function":{"name":"read_file","arguments":"{\"path\":\"a.go\"}"}},
	  {"type":"function","function":{"name":"read_file","arguments":"{\"path\":\"b.go\"}"}}
	]}}]}`
	srv, rec := stubServer(t, http.StatusOK, body)
	c := newClient(t, openaicompat.Config{BaseURL: srv.URL, Model: "m", HTTPClient: srv.Client()})

	resp, err := c.Generate(context.Background(), provider.Request{
		Messages: []provider.Message{{Role: "user", Content: "hi"}},
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	assertUsableCallIDs(t, resp.ToolCalls, 2)

	// Determinism: the same response yields the same ids.
	again, err := c.Generate(context.Background(), provider.Request{
		Messages: []provider.Message{{Role: "user", Content: "hi"}},
	})
	if err != nil {
		t.Fatalf("Generate again: %v", err)
	}
	for i := range resp.ToolCalls {
		if resp.ToolCalls[i].ID != again.ToolCalls[i].ID {
			t.Errorf("call %d id = %q then %q, want the same id both times",
				i, resp.ToolCalls[i].ID, again.ToolCalls[i].ID)
		}
	}

	// Feeding the turn back keeps every result paired with its call.
	results := make([]provider.ToolResult, 0, len(resp.ToolCalls))
	for _, tc := range resp.ToolCalls {
		results = append(results, provider.ToolResult{CallID: tc.ID, Name: tc.Name, Output: "ok"})
	}
	if _, err := c.Generate(context.Background(), provider.Request{
		Messages: []provider.Message{
			{Role: "user", Content: "hi"},
			{Role: "model", ToolCalls: resp.ToolCalls},
			{Role: "tool", ToolResults: results},
		},
	}); err != nil {
		t.Fatalf("Generate round-trip: %v", err)
	}
	assertToolCallsPaired(t, rec.request(t).Messages)
}

// Duplicated ids are the same failure wearing a different hat: two results
// keyed identically cannot be told apart.
func TestGenerate_ToleratesDuplicateToolCallIDs(t *testing.T) {
	resp, err := answering(t, `{"choices":[{"message":{"tool_calls":[
	  {"id":"call_x","type":"function","function":{"name":"read_file","arguments":"{\"path\":\"a.go\"}"}},
	  {"id":"call_x","type":"function","function":{"name":"read_file","arguments":"{\"path\":\"b.go\"}"}},
	  {"id":"call_x","type":"function","function":{"name":"read_file","arguments":"{\"path\":\"c.go\"}"}}
	]}}]}`)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	assertUsableCallIDs(t, resp.ToolCalls, 3)
	// The first call keeps the id the server chose; only the collisions move.
	if resp.ToolCalls[0].ID != "call_x" {
		t.Errorf("first id = %q, want the server's own call_x", resp.ToolCalls[0].ID)
	}
	// Arguments stay attached to the right call.
	for i, want := range []string{"a.go", "b.go", "c.go"} {
		if got := resp.ToolCalls[i].Args["path"]; got != want {
			t.Errorf("call %d path = %v, want %q", i, got, want)
		}
	}
}

// Some runtimes emit tool arguments as a JSON object where the protocol says
// JSON-encoded string.
func TestGenerate_ToleratesToolArgumentsAsObject(t *testing.T) {
	resp, err := answering(t, `{"choices":[{"message":{"tool_calls":[
	  {"id":"c1","type":"function","function":{"name":"read_file","arguments":{"path":"main.go","limit":20}}}
	]}}]}`)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(resp.ToolCalls) != 1 {
		t.Fatalf("tool calls = %+v, want 1", resp.ToolCalls)
	}
	if got := resp.ToolCalls[0].Args["path"]; got != "main.go" {
		t.Errorf("args = %v, want path=main.go", resp.ToolCalls[0].Args)
	}
	if got := resp.ToolCalls[0].Args["limit"]; got != float64(20) {
		t.Errorf("args = %v, want limit=20", resp.ToolCalls[0].Args)
	}
}

// Arguments that parse as nothing at all still leave a call the agent loop can
// dispatch: the tool then rejects the empty arguments and the model gets a turn
// to correct itself, which beats abandoning the Review.
func TestGenerate_ToleratesUnparseableToolArguments(t *testing.T) {
	for _, arguments := range []string{`"not json at all"`, `"{ unclosed"`, `""`, `null`, `42`} {
		resp, err := answering(t, `{"choices":[{"message":{"tool_calls":[
		  {"id":"c1","type":"function","function":{"name":"read_file","arguments":`+arguments+`}}
		]}}]}`)
		if err != nil {
			t.Fatalf("arguments %s: Generate: %v", arguments, err)
		}
		if len(resp.ToolCalls) != 1 {
			t.Fatalf("arguments %s: tool calls = %+v, want 1", arguments, resp.ToolCalls)
		}
		if got := resp.ToolCalls[0]; got.Name != "read_file" || got.ID != "c1" {
			t.Errorf("arguments %s: call = %+v, want the call itself intact", arguments, got)
		}
		if len(resp.ToolCalls[0].Args) != 0 {
			t.Errorf("arguments %s: args = %v, want none", arguments, resp.ToolCalls[0].Args)
		}
	}
}

// Some gateways return content as an array of parts rather than a string. The
// Report text is the product, so losing it to a decode error is not an option.
func TestGenerate_ToleratesContentAsParts(t *testing.T) {
	resp, err := answering(t, `{"choices":[{"message":{"content":[
	  {"type":"text","text":"## Findings\n"},
	  {"type":"text","text":"none"}
	]}}]}`)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if resp.Text != "## Findings\nnone" {
		t.Errorf("text = %q, want the parts joined", resp.Text)
	}
}

// Content in a shape nobody anticipated yields no text rather than a failed
// turn — including the null a server sends alongside tool calls.
func TestGenerate_ToleratesUnreadableContent(t *testing.T) {
	for _, content := range []string{`null`, `42`, `true`, `{"text":"nested"}`} {
		resp, err := answering(t, `{"choices":[{"message":{"content":`+content+`,"tool_calls":[
		  {"id":"c1","type":"function","function":{"name":"read_file","arguments":"{}"}}
		]}}]}`)
		if err != nil {
			t.Fatalf("content %s: Generate: %v", content, err)
		}
		if resp.Text != "" {
			t.Errorf("content %s: text = %q, want empty", content, resp.Text)
		}
		// The tool call beside it still survives, which is the point.
		if len(resp.ToolCalls) != 1 {
			t.Errorf("content %s: tool calls = %+v, want 1", content, resp.ToolCalls)
		}
	}
}

// --- Base URLs ---------------------------------------------------------------
//
// The /v1 suffix is mandatory and some services do not serve the API at the
// domain root, so a base URL routinely carries a path. Neither a trailing slash
// nor that path may be mangled.

func TestGenerate_JoinsBaseURLWithoutManglingIt(t *testing.T) {
	cases := []struct {
		name   string
		suffix string
		want   string
	}{
		{"bare host", "", "/chat/completions"},
		{"trailing slash", "/", "/chat/completions"},
		{"path component", "/api/v1", "/api/v1/chat/completions"},
		{"path component with trailing slash", "/api/v1/", "/api/v1/chat/completions"},
		{"several trailing slashes", "/v1///", "/v1/chat/completions"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, rec := stubServer(t, http.StatusOK, `{"choices":[{"message":{"content":"ok"}}]}`)
			c := newClient(t, openaicompat.Config{
				BaseURL:    srv.URL + tc.suffix,
				Model:      "m",
				HTTPClient: srv.Client(),
			})

			if _, err := c.Generate(context.Background(), provider.Request{
				Messages: []provider.Message{{Role: "user", Content: "hi"}},
			}); err != nil {
				t.Fatalf("Generate: %v", err)
			}
			if _, path, _, _ := rec.snapshot(); path != tc.want {
				t.Errorf("path = %q, want %q", path, tc.want)
			}
		})
	}
}

// A base URL carrying a query string keeps it: some hosted endpoints pin an API
// version that way, and it belongs at the end of the URL, not in the middle of
// the path.
func TestGenerate_PreservesBaseURLQueryString(t *testing.T) {
	srv, rec := stubServer(t, http.StatusOK, `{"choices":[{"message":{"content":"ok"}}]}`)
	c := newClient(t, openaicompat.Config{
		BaseURL:    srv.URL + "/v1?api-version=2024-02-01",
		Model:      "m",
		HTTPClient: srv.Client(),
	})

	if _, err := c.Generate(context.Background(), provider.Request{
		Messages: []provider.Message{{Role: "user", Content: "hi"}},
	}); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if _, path, _, _ := rec.snapshot(); path != "/v1/chat/completions" {
		t.Errorf("path = %q, want /v1/chat/completions", path)
	}
	if got := rec.rawQuery(); got != "api-version=2024-02-01" {
		t.Errorf("query = %q, want api-version=2024-02-01", got)
	}
}

// An unset base URL means OpenAI itself, /v1 suffix included.
func TestGenerate_DefaultsToOpenAIEndpoint(t *testing.T) {
	if openaicompat.DefaultBaseURL != "https://api.openai.com/v1" {
		t.Errorf("DefaultBaseURL = %q", openaicompat.DefaultBaseURL)
	}

	capture := &urlCapture{}
	c := newClient(t, openaicompat.Config{Model: "m", HTTPClient: &http.Client{Transport: capture}})
	if _, err := c.Generate(context.Background(), provider.Request{
		Messages: []provider.Message{{Role: "user", Content: "hi"}},
	}); err == nil {
		t.Fatal("expected the stub transport's error")
	}
	if want := "https://api.openai.com/v1/chat/completions"; capture.url != want {
		t.Errorf("requested %q, want %q", capture.url, want)
	}
}

// urlCapture records the URL a request was addressed to and fails it without
// leaving the process. It exists for the one endpoint a test server cannot
// stand in for: the default, which is a real host Argus must never actually
// call from a test.
type urlCapture struct{ url string }

func (u *urlCapture) RoundTrip(r *http.Request) (*http.Response, error) {
	u.url = r.URL.String()
	return nil, errors.New("stub transport: no network in tests")
}

func TestNew_RejectsUnusableConfig(t *testing.T) {
	cases := []struct {
		name string
		cfg  openaicompat.Config
	}{
		{"no model", openaicompat.Config{BaseURL: "https://api.example.com/v1"}},
		{"blank model", openaicompat.Config{Model: "  ", BaseURL: "https://api.example.com/v1"}},
		{"base URL without scheme", openaicompat.Config{Model: "m", BaseURL: "localhost:11434/v1"}},
		{"base URL without host", openaicompat.Config{Model: "m", BaseURL: "https:///v1"}},
		{"unsupported scheme", openaicompat.Config{Model: "m", BaseURL: "ftp://example.com/v1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := openaicompat.New(tc.cfg); err == nil {
				t.Errorf("New(%+v) succeeded, want an error", tc.cfg)
			}
		})
	}
}

func TestNew_AcceptsKeylessLocalRuntime(t *testing.T) {
	if _, err := openaicompat.New(openaicompat.Config{
		Model:   "qwen2.5-coder",
		BaseURL: "http://localhost:11434/v1",
	}); err != nil {
		t.Errorf("New without an API key: %v", err)
	}
}

// --- ListModels --------------------------------------------------------------

func TestListModels_ReturnsIDs(t *testing.T) {
	srv, rec := stubServer(t, http.StatusOK, `{"object":"list","data":[
	  {"id":"gpt-4o-mini","object":"model","owned_by":"openai"},
	  {"id":"vendor/model-name","object":"model"}
	]}`)
	c := newClient(t, openaicompat.Config{APIKey: "sk-test", BaseURL: srv.URL + "/api/v1", Model: "m", HTTPClient: srv.Client()})

	models, err := c.ListModels(context.Background())
	if err != nil {
		t.Fatalf("ListModels: %v", err)
	}

	method, path, header, _ := rec.snapshot()
	if method != http.MethodGet {
		t.Errorf("method = %q, want GET", method)
	}
	if path != "/api/v1/models" {
		t.Errorf("path = %q, want /api/v1/models", path)
	}
	if got := header.Get("Authorization"); got != "Bearer sk-test" {
		t.Errorf("Authorization = %q", got)
	}
	want := []string{"gpt-4o-mini", "vendor/model-name"}
	if len(models) != len(want) {
		t.Fatalf("models = %v, want %v", models, want)
	}
	for i := range want {
		if models[i] != want[i] {
			t.Errorf("model %d = %q, want %q", i, models[i], want[i])
		}
	}
}

// An entry with no id tells the caller nothing and cannot be matched against a
// configured model, so it is dropped rather than returned as an empty name.
func TestListModels_SkipsEntriesWithoutIDs(t *testing.T) {
	srv, _ := stubServer(t, http.StatusOK, `{"data":[{"id":""},{"object":"model"},{"id":"llama3.2"}]}`)
	c := newClient(t, openaicompat.Config{BaseURL: srv.URL, Model: "m", HTTPClient: srv.Client()})

	models, err := c.ListModels(context.Background())
	if err != nil {
		t.Fatalf("ListModels: %v", err)
	}
	if len(models) != 1 || models[0] != "llama3.2" {
		t.Errorf("models = %v, want [llama3.2]", models)
	}
}

// A server with no models to report is reachable, which is half of what the
// probe is asking. That is not an error.
func TestListModels_ToleratesEmptyList(t *testing.T) {
	srv, _ := stubServer(t, http.StatusOK, `{"object":"list","data":[]}`)
	c := newClient(t, openaicompat.Config{BaseURL: srv.URL, Model: "m", HTTPClient: srv.Client()})

	models, err := c.ListModels(context.Background())
	if err != nil {
		t.Fatalf("ListModels: %v", err)
	}
	if len(models) != 0 {
		t.Errorf("models = %v, want none", models)
	}
}

// The probe calls this first precisely so a wrong URL or a bad key surfaces as
// itself. It must never be reported as a tool-calling verdict.
func TestListModels_ReportsServerErrors(t *testing.T) {
	srv, _ := stubServer(t, http.StatusUnauthorized, `{"error":{"message":"Incorrect API key provided"}}`)
	c := newClient(t, openaicompat.Config{APIKey: "sk-wrong", BaseURL: srv.URL, Model: "m", HTTPClient: srv.Client()})

	_, err := c.ListModels(context.Background())
	if err == nil {
		t.Fatal("expected an error")
	}
	if errors.Is(err, openaicompat.ErrToolCallingUnsupported) {
		t.Errorf("error = %v, want the server's own complaint", err)
	}
	for _, want := range []string{"401", "Incorrect API key provided"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %v, want it to contain %q", err, want)
		}
	}
}

// --- Errors ------------------------------------------------------------------

// A server that refuses a request carrying tool declarations is telling the user
// their model cannot do the one thing Argus requires. That has to arrive as a
// sentence, not as an HTTP dump from a server the user did not write.
func TestGenerate_TranslatesToolRejectionIntoPlainLanguage(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusUnprocessableEntity} {
		srv, _ := stubServer(t, status,
			`{"error":{"message":"\"tools\" is not supported by this model","type":"invalid_request_error"}}`)
		c := newClient(t, openaicompat.Config{BaseURL: srv.URL, Model: "tiny-local", HTTPClient: srv.Client()})

		_, err := c.Generate(context.Background(), provider.Request{
			Messages: []provider.Message{{Role: "user", Content: "hi"}},
			Tools:    []provider.ToolDecl{{Name: "read_file"}},
		})
		if err == nil {
			t.Fatalf("status %d: expected an error", status)
		}
		if !errors.Is(err, openaicompat.ErrToolCallingUnsupported) {
			t.Errorf("status %d: error = %v, want ErrToolCallingUnsupported", status, err)
		}
		msg := err.Error()
		if !strings.Contains(strings.ToLower(msg), "tool calling") {
			t.Errorf("status %d: message = %q, want it to name tool calling", status, msg)
		}
		if !strings.Contains(msg, "tiny-local") {
			t.Errorf("status %d: message = %q, want it to name the model", status, msg)
		}
		// The verdict leads, but the server's own words survive it: a claim about
		// a model's capabilities is one the user should be able to check.
		if !strings.Contains(msg, "is not supported by this model") {
			t.Errorf("status %d: message = %q, want the endpoint's own words kept", status, msg)
		}
		// Still not a raw HTTP dump: no status code, no JSON envelope.
		for _, leak := range []string{"status ", "invalid_request_error", "{"} {
			if strings.Contains(msg, leak) {
				t.Errorf("status %d: message = %q, want no raw HTTP detail (%q)", status, msg, leak)
			}
		}
	}
}

// The agent loop declares its tools on every turn of every Review, so "a 4xx
// arrived while tools were in flight" is not evidence of anything on its own. A
// client error the server blames on something else must be reported as that
// something else — a context window that overflowed on turn 30 is a different
// problem with a different fix, and answering it with a verdict on the model's
// capabilities is the misdirection this Provider exists to end.
func TestGenerate_DoesNotBlameToolCallingForAnUnrelatedBadRequest(t *testing.T) {
	for _, tools := range [][]provider.ToolDecl{
		nil,
		{{Name: "read_file"}},
	} {
		srv, _ := stubServer(t, http.StatusBadRequest,
			`{"error":{"message":"This model's maximum context length is 8192 tokens"}}`)
		c := newClient(t, openaicompat.Config{BaseURL: srv.URL, Model: "m", HTTPClient: srv.Client()})

		_, err := c.Generate(context.Background(), provider.Request{
			Messages: []provider.Message{{Role: "user", Content: "hi"}},
			Tools:    tools,
		})
		if err == nil {
			t.Fatalf("%d tool declarations: expected an error", len(tools))
		}
		if errors.Is(err, openaicompat.ErrToolCallingUnsupported) {
			t.Errorf("%d tool declarations: error = %v, want the server's own complaint, not a tool-calling verdict",
				len(tools), err)
		}
		if !strings.Contains(err.Error(), "maximum context length is 8192") {
			t.Errorf("%d tool declarations: error = %v, want the server's message", len(tools), err)
		}
	}
}

// A long error body is quoted, not dumped whole: a proxy can answer with an
// entire HTML page.
func TestGenerate_BoundsQuotedErrorBody(t *testing.T) {
	body := "upstream failure: " + strings.Repeat("padding ", 4000)
	srv, _ := stubServer(t, http.StatusBadGateway, body)
	c := newClient(t, openaicompat.Config{BaseURL: srv.URL, Model: "m", HTTPClient: srv.Client()})

	_, err := c.Generate(context.Background(), provider.Request{
		Messages: []provider.Message{{Role: "user", Content: "hi"}},
	})
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "upstream failure") {
		t.Errorf("error = %v, want the start of the body", err)
	}
	if len(err.Error()) >= len(body) {
		t.Errorf("error is %d bytes for a %d-byte body, want it bounded", len(err.Error()), len(body))
	}
}

// A bad key, a wrong URL and a rate limit are unambiguous, and each has its own
// fix. Reporting any of them as "your model cannot call tools" would point the
// user at the wrong problem — the exact failure this Provider exists to end.
func TestGenerate_DoesNotBlameToolCallingForUnrelatedClientErrors(t *testing.T) {
	for status, detail := range map[int]string{
		http.StatusUnauthorized:    "invalid api key",
		http.StatusForbidden:       "access denied",
		http.StatusNotFound:        "model not found",
		http.StatusTooManyRequests: "rate limit reached",
		http.StatusRequestTimeout:  "request timed out",
	} {
		srv, _ := stubServer(t, status, `{"error":{"message":"`+detail+`"}}`)
		c := newClient(t, openaicompat.Config{BaseURL: srv.URL, Model: "m", HTTPClient: srv.Client()})

		_, err := c.Generate(context.Background(), provider.Request{
			Messages: []provider.Message{{Role: "user", Content: "hi"}},
			Tools:    []provider.ToolDecl{{Name: "read_file"}},
		})
		if err == nil {
			t.Fatalf("status %d: expected an error", status)
		}
		if errors.Is(err, openaicompat.ErrToolCallingUnsupported) {
			t.Errorf("status %d: error = %v, want it reported as itself", status, err)
		}
		if !strings.Contains(err.Error(), detail) {
			t.Errorf("status %d: error = %v, want it to carry %q", status, err, detail)
		}
	}
}

// Anything else non-2xx must quote enough of the server's own words to act on.
func TestGenerate_ServerErrorCarriesActionableDetail(t *testing.T) {
	srv, _ := stubServer(t, http.StatusInternalServerError,
		`{"error":{"message":"failed to load model: out of VRAM"}}`)
	c := newClient(t, openaicompat.Config{BaseURL: srv.URL, Model: "m", HTTPClient: srv.Client()})

	_, err := c.Generate(context.Background(), provider.Request{
		Messages: []provider.Message{{Role: "user", Content: "hi"}},
	})
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{"500", "out of VRAM"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %v, want it to contain %q", err, want)
		}
	}
}

// A 200 carrying no choices is the one shape tolerance cannot absorb: there is
// nothing to hand the agent loop, and returning an empty answer would end the
// Session silently as if the model had simply finished.
func TestGenerate_RejectsResponseWithNoChoices(t *testing.T) {
	for _, body := range []string{`{}`, `{"choices":[]}`, `{"choices":null}`} {
		srv, _ := stubServer(t, http.StatusOK, body)
		c := newClient(t, openaicompat.Config{BaseURL: srv.URL, Model: "m", HTTPClient: srv.Client()})

		if _, err := c.Generate(context.Background(), provider.Request{
			Messages: []provider.Message{{Role: "user", Content: "hi"}},
		}); err == nil {
			t.Errorf("body %s: expected an error", body)
		}
	}
}

// A server that answers non-2xx with an unstructured body still has to be
// quoted: plenty of proxies return plain text or HTML.
func TestGenerate_ServerErrorQuotesUnstructuredBody(t *testing.T) {
	srv, _ := stubServer(t, http.StatusBadGateway, `upstream connect error`)
	c := newClient(t, openaicompat.Config{BaseURL: srv.URL, Model: "m", HTTPClient: srv.Client()})

	_, err := c.Generate(context.Background(), provider.Request{
		Messages: []provider.Message{{Role: "user", Content: "hi"}},
	})
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "upstream connect error") {
		t.Errorf("error = %v, want the raw body quoted", err)
	}
}

// assertUsableCallIDs checks the property the agent loop depends on: every call
// has a non-empty id, and no two calls share one.
func assertUsableCallIDs(t *testing.T, calls []provider.ToolCall, want int) {
	t.Helper()
	if len(calls) != want {
		t.Fatalf("tool calls = %+v, want %d", calls, want)
	}
	seen := map[string]bool{}
	for i, tc := range calls {
		if tc.ID == "" {
			t.Errorf("call %d (%s) has an empty id", i, tc.Name)
		}
		if seen[tc.ID] {
			t.Errorf("call %d reuses id %q", i, tc.ID)
		}
		seen[tc.ID] = true
	}
}

// assertToolCallsPaired checks that every tool message on the wire refers to a
// tool call some assistant message actually declared.
func assertToolCallsPaired(t *testing.T, msgs []wireMessage) {
	t.Helper()
	declared := map[string]bool{}
	for _, m := range msgs {
		for _, tc := range m.ToolCalls {
			if tc.ID == "" {
				t.Errorf("assistant message declared a tool call with no id: %+v", tc)
			}
			declared[tc.ID] = true
		}
	}
	tools := 0
	for _, m := range msgs {
		if m.Role != "tool" {
			continue
		}
		tools++
		if !declared[m.ToolCallID] {
			t.Errorf("tool message references id %q, which no assistant message declared", m.ToolCallID)
		}
	}
	if tools == 0 {
		t.Errorf("no tool messages on the wire: %+v", msgs)
	}
}

// jsonDiff reports a human-readable difference between two values compared as
// JSON, or "" when they match.
func jsonDiff(t *testing.T, want, got any) string {
	t.Helper()
	wb, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal want: %v", err)
	}
	gb, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal got: %v", err)
	}
	var wn, gn any
	_ = json.Unmarshal(wb, &wn)
	_ = json.Unmarshal(gb, &gn)
	wc, _ := json.Marshal(wn)
	gc, _ := json.Marshal(gn)
	if string(wc) == string(gc) {
		return ""
	}
	return fmt.Sprintf("got %s, want %s", gc, wc)
}
