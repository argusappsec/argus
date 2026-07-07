package mcp

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/argusappsec/argus/pkg/audit"
	"github.com/argusappsec/argus/pkg/auth"
	"github.com/argusappsec/argus/pkg/daemon"
)

const testToken = "s3cret-bearer-token"

// testServer builds an MCP channel over a temp home whose users.yaml carries a
// single analyst Person with one MCP token whose hash matches testToken.
func testServer(t *testing.T) (*Server, string) {
	t.Helper()
	home := t.TempDir()
	users := "persons:\n" +
		"  - id: davide\n" +
		"    role: analyst\n" +
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
		Home:  home,
		Auth:  auth.NewResolver(usersPath),
		Audit: aud,
	}
	return NewServer(dc, Options{Addr: ":0"}), auditPath
}

// post sends a JSON-RPC body to the MCP endpoint with the given bearer token
// ("" omits the Authorization header) and returns the recorder.
func post(t *testing.T, s *Server, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", endpointPath, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	s.handle(rec, req)
	return rec
}

func TestHandle_MissingTokenIsRejected(t *testing.T) {
	s, auditPath := testServer(t)
	rec := post(t, s, "", `{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	if rec.Code != 401 {
		t.Fatalf("code = %d, want 401", rec.Code)
	}
	// No anonymous access: the rejection is audited but unattributed.
	e := findEvent(t, auditPath, "mcp_unauthenticated")
	if e == nil {
		t.Fatal("expected an mcp_unauthenticated audit event")
	}
	if _, ok := e.Data["principal"]; ok {
		t.Errorf("an unauthenticated rejection must not be attributed to a principal: %v", e.Data)
	}
}

func TestHandle_UnknownTokenIsRejected(t *testing.T) {
	s, _ := testServer(t)
	rec := post(t, s, "not-the-token", `{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	if rec.Code != 401 {
		t.Fatalf("code = %d, want 401", rec.Code)
	}
}

func TestHandle_InitializeHandshake(t *testing.T) {
	s, auditPath := testServer(t)
	rec := post(t, s, testToken, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"cursor","version":"1.0"}}}`)
	if rec.Code != 200 {
		t.Fatalf("code = %d, want 200", rec.Code)
	}

	var resp struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  initializeResult `json:"result"`
		Error   *rpcError        `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v\nbody: %s", err, rec.Body.String())
	}
	if resp.JSONRPC != "2.0" {
		t.Errorf("jsonrpc = %q, want 2.0", resp.JSONRPC)
	}
	if string(resp.ID) != "1" {
		t.Errorf("id = %s, want 1", resp.ID)
	}
	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}
	if resp.Result.ProtocolVersion != protocolVersion {
		t.Errorf("protocolVersion = %q, want %q", resp.Result.ProtocolVersion, protocolVersion)
	}
	if resp.Result.ServerInfo.Name != serverName {
		t.Errorf("serverInfo.name = %q, want %q", resp.Result.ServerInfo.Name, serverName)
	}
	if resp.Result.Capabilities == nil {
		t.Error("capabilities must be a (possibly empty) object, not null")
	}

	// Every authenticated request is attributed to the resolved Person.
	e := findEvent(t, auditPath, "mcp_request")
	if e == nil {
		t.Fatal("expected an mcp_request audit event")
	}
	if e.Data["principal"] != "davide" {
		t.Errorf("principal = %v, want davide", e.Data["principal"])
	}
	if e.Data["method"] != "initialize" {
		t.Errorf("method = %v, want initialize", e.Data["method"])
	}
	if e.Data["identity"] != "mcp:"+auth.SHA256Hex(testToken) {
		t.Errorf("identity = %v, want the mcp:<token-hash> surface", e.Data["identity"])
	}
}

func TestHandle_InitializedNotificationGets202(t *testing.T) {
	s, _ := testServer(t)
	rec := post(t, s, testToken, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	if rec.Code != 202 {
		t.Fatalf("code = %d, want 202 (notifications carry no response)", rec.Code)
	}
	if strings.TrimSpace(rec.Body.String()) != "" {
		t.Errorf("notification response body = %q, want empty", rec.Body.String())
	}
}

func TestHandle_UnknownMethodIsMethodNotFound(t *testing.T) {
	s, _ := testServer(t)
	rec := post(t, s, testToken, `{"jsonrpc":"2.0","id":7,"method":"prompts/list"}`)
	if rec.Code != 200 {
		t.Fatalf("code = %d, want 200 (JSON-RPC errors ride a 200)", rec.Code)
	}
	var resp rpcResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if resp.Error == nil || resp.Error.Code != codeMethodNotFound {
		t.Fatalf("error = %+v, want method-not-found (%d)", resp.Error, codeMethodNotFound)
	}
}

func TestHandle_ParseErrorCarriesNullID(t *testing.T) {
	s, _ := testServer(t)
	rec := post(t, s, testToken, `{not valid json`)
	if rec.Code != 200 {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
	// JSON-RPC 2.0 §5: when the id cannot be determined it MUST be null, present
	// in the frame — not omitted.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("parse: %v", err)
	}
	id, ok := raw["id"]
	if !ok {
		t.Fatal("parse-error response must include an id field")
	}
	if string(id) != "null" {
		t.Errorf("id = %s, want null", id)
	}
	var resp rpcResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if resp.Error == nil || resp.Error.Code != codeParseError {
		t.Fatalf("error = %+v, want parse-error (%d)", resp.Error, codeParseError)
	}
}

func TestHandle_PingNotificationGetsNoResponse(t *testing.T) {
	s, _ := testServer(t)
	// A ping with no id is a notification: processed, but no response written.
	rec := post(t, s, testToken, `{"jsonrpc":"2.0","method":"ping"}`)
	if rec.Code != 202 {
		t.Fatalf("code = %d, want 202 (notification gets no response)", rec.Code)
	}
	if strings.TrimSpace(rec.Body.String()) != "" {
		t.Errorf("body = %q, want empty", rec.Body.String())
	}
}

func TestHandle_NonPostIsRejected(t *testing.T) {
	s, _ := testServer(t)
	req := httptest.NewRequest("GET", endpointPath, nil)
	rec := httptest.NewRecorder()
	s.handle(rec, req)
	if rec.Code != 405 {
		t.Fatalf("code = %d, want 405", rec.Code)
	}
}

// findEvent returns the first audit event of the given type, or nil.
func findEvent(t *testing.T, path, typ string) *audit.Event {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.SplitSeq(strings.TrimSpace(string(b)), "\n") {
		if line == "" {
			continue
		}
		var e audit.Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("parse audit line: %v", err)
		}
		if e.Type == typ {
			return &e
		}
	}
	return nil
}
