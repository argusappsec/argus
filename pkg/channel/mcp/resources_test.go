package mcp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/argusappsec/argus/pkg/auth"
)

// seedOrgKnowledge writes a SOUL, a CONTEXT document, and a report under the
// server's daemon home so the resource surface has something to expose.
func seedOrgKnowledge(t *testing.T, s *Server) {
	t.Helper()
	home := s.dc.Home
	mustWrite(t, filepath.Join(home, "SOUL.md"), "---\ncompany: Acme\n---\nWe ship fast and patch faster.")
	mustWrite(t, filepath.Join(home, "context", "architecture.md"), "# Architecture\nMonolith on AWS behind an ALB.")
	mustWrite(t, filepath.Join(home, "reports", "acme_api", "abc123.md"), "# Security review\nNo findings this run.")
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// listResult parses a resources/list response.
func listResult(t *testing.T, rec []byte) resourcesListResult {
	t.Helper()
	var resp struct {
		Result resourcesListResult `json:"result"`
		Error  *rpcError           `json:"error"`
	}
	if err := json.Unmarshal(rec, &resp); err != nil {
		t.Fatalf("parse resources/list: %v\nbody: %s", err, rec)
	}
	if resp.Error != nil {
		t.Fatalf("unexpected JSON-RPC error: %+v", resp.Error)
	}
	return resp.Result
}

// findResource returns the declared resource with the given URI, or nil.
func findResource(res resourcesListResult, uri string) *resourceDecl {
	for i := range res.Resources {
		if res.Resources[i].URI == uri {
			return &res.Resources[i]
		}
	}
	return nil
}

func TestInitialize_AdvertisesResourcesCapability(t *testing.T) {
	s, _ := reviewServer(t, &scriptedProvider{responses: textAnswer("ok")}, auth.RoleAnalyst)
	rec := post(t, s, testToken, `{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	var resp struct {
		Result initializeResult `json:"result"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, ok := resp.Result.Capabilities["resources"]; !ok {
		t.Errorf("initialize must advertise the resources capability, got %+v", resp.Result.Capabilities)
	}
}

func TestResourcesList_ExposesSoulContextAndReports(t *testing.T) {
	s, auditPath := reviewServer(t, &scriptedProvider{responses: textAnswer("ok")}, auth.RoleAnalyst)
	seedOrgKnowledge(t, s)

	rec := post(t, s, testToken, `{"jsonrpc":"2.0","id":2,"method":"resources/list"}`)
	if rec.Code != 200 {
		t.Fatalf("code = %d", rec.Code)
	}
	res := listResult(t, rec.Body.Bytes())

	if r := findResource(res, soulURI); r == nil {
		t.Errorf("resources/list must expose SOUL at %s, got %+v", soulURI, res.Resources)
	} else if r.MimeType != mimeMarkdown {
		t.Errorf("SOUL mimeType = %q, want %q", r.MimeType, mimeMarkdown)
	}
	if findResource(res, contextURIPrefix+"architecture") == nil {
		t.Errorf("resources/list must expose the CONTEXT document, got %+v", res.Resources)
	}
	if findResource(res, reportURIPrefix+"acme_api/abc123") == nil {
		t.Errorf("resources/list must expose the recent report, got %+v", res.Resources)
	}

	// The listing is attributed to the resolved Person.
	e := findEvent(t, auditPath, "mcp_resources_list")
	if e == nil || e.Data["principal"] != "davide" {
		t.Errorf("expected an mcp_resources_list event attributed to davide, got %+v", e)
	}
}

func TestResourcesList_OmitsAbsentKnowledge(t *testing.T) {
	// A fresh daemon with no SOUL/context/reports lists nothing — absent knowledge
	// is simply not advertised, never an error.
	s, _ := reviewServer(t, &scriptedProvider{responses: textAnswer("ok")}, auth.RoleAnalyst)
	rec := post(t, s, testToken, `{"jsonrpc":"2.0","id":2,"method":"resources/list"}`)
	res := listResult(t, rec.Body.Bytes())
	if len(res.Resources) != 0 {
		t.Errorf("an empty daemon must expose no resources, got %+v", res.Resources)
	}
	if res.Resources == nil {
		t.Error("resources must serialize as [], not null")
	}
}

func TestResourceRead_ReturnsEachResourceBody(t *testing.T) {
	s, auditPath := reviewServer(t, &scriptedProvider{responses: textAnswer("ok")}, auth.RoleAnalyst)
	seedOrgKnowledge(t, s)

	cases := []struct {
		uri  string
		want string
	}{
		{soulURI, "patch faster"},
		{contextURIPrefix + "architecture", "Monolith on AWS"},
		{reportURIPrefix + "acme_api/abc123", "No findings this run"},
	}
	for _, c := range cases {
		body := `{"jsonrpc":"2.0","id":3,"method":"resources/read","params":{"uri":"` + c.uri + `"}}`
		rec := post(t, s, testToken, body)
		if rec.Code != 200 {
			t.Fatalf("%s: code = %d", c.uri, rec.Code)
		}
		var resp struct {
			Result readResourceResult `json:"result"`
			Error  *rpcError          `json:"error"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("%s: parse: %v", c.uri, err)
		}
		if resp.Error != nil {
			t.Fatalf("%s: unexpected error: %+v", c.uri, resp.Error)
		}
		if len(resp.Result.Contents) != 1 {
			t.Fatalf("%s: contents = %d, want 1", c.uri, len(resp.Result.Contents))
		}
		got := resp.Result.Contents[0]
		if got.URI != c.uri {
			t.Errorf("%s: content uri = %q", c.uri, got.URI)
		}
		if !strings.Contains(got.Text, c.want) {
			t.Errorf("%s: text = %q, want it to contain %q", c.uri, got.Text, c.want)
		}
	}

	// Reads are attributed to the resolved Person.
	e := findEvent(t, auditPath, "mcp_resource_read")
	if e == nil || e.Data["principal"] != "davide" {
		t.Errorf("expected an mcp_resource_read event attributed to davide, got %+v", e)
	}
}

func TestResourceRead_UnknownURIIsNotFound(t *testing.T) {
	s, _ := reviewServer(t, &scriptedProvider{responses: textAnswer("ok")}, auth.RoleAnalyst)
	body := `{"jsonrpc":"2.0","id":4,"method":"resources/read","params":{"uri":"argus://nope"}}`
	rec := post(t, s, testToken, body)
	var resp rpcResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Error == nil || resp.Error.Code != codeResourceNotFound {
		t.Fatalf("error = %+v, want resource-not-found (%d)", resp.Error, codeResourceNotFound)
	}
}

func TestResourceRead_RejectsTraversal(t *testing.T) {
	s, _ := reviewServer(t, &scriptedProvider{responses: textAnswer("ok")}, auth.RoleAnalyst)
	// Place a secret outside the context dir; a traversal URI must not reach it.
	mustWrite(t, filepath.Join(s.dc.Home, "users.yaml.bak"), "secret")
	body := `{"jsonrpc":"2.0","id":5,"method":"resources/read","params":{"uri":"argus://context/../users.yaml.bak"}}`
	rec := post(t, s, testToken, body)
	var resp rpcResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Error == nil {
		t.Fatal("a traversal URI must be rejected, not served")
	}
}

func TestResourceRead_RejectsReportTraversal(t *testing.T) {
	s, _ := reviewServer(t, &scriptedProvider{responses: textAnswer("ok")}, auth.RoleAnalyst)
	mustWrite(t, filepath.Join(s.dc.Home, "users.yaml.bak"), "secret")
	// A report handle's slug/sha must not climb out of the reports dir.
	body := `{"jsonrpc":"2.0","id":5,"method":"resources/read","params":{"uri":"argus://report/../users.yaml.bak/x"}}`
	rec := post(t, s, testToken, body)
	var resp rpcResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Error == nil {
		t.Fatal("a traversal report handle must be rejected, not served")
	}
}

func TestResources_NonReadingRoleSeesNothingAndCannotRead(t *testing.T) {
	// A non-reading role (a service token holder) gets an empty listing and a
	// denied read — read access respects the caller's Role at the resource layer.
	s, auditPath := reviewServer(t, &scriptedProvider{responses: textAnswer("ok")}, auth.RoleMirrorRead)
	seedOrgKnowledge(t, s)

	listRec := post(t, s, testToken, `{"jsonrpc":"2.0","id":2,"method":"resources/list"}`)
	if got := listResult(t, listRec.Body.Bytes()); len(got.Resources) != 0 {
		t.Errorf("a non-reading role must see no resources, got %+v", got.Resources)
	}
	if findEvent(t, auditPath, "mcp_resources_list_denied") == nil {
		t.Error("expected an mcp_resources_list_denied audit event")
	}

	readRec := post(t, s, testToken, `{"jsonrpc":"2.0","id":3,"method":"resources/read","params":{"uri":"`+soulURI+`"}}`)
	var resp rpcResponse
	if err := json.Unmarshal(readRec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Error == nil || resp.Error.Code != codeForbidden {
		t.Fatalf("a non-reading role's read must be denied with forbidden (%d), got %+v", codeForbidden, resp.Error)
	}
	if findEvent(t, auditPath, "mcp_resource_read_denied") == nil {
		t.Error("expected an mcp_resource_read_denied audit event")
	}
}
