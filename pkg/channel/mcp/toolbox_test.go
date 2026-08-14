package mcp

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/argusappsec/argus/pkg/auth"
	"github.com/argusappsec/argus/pkg/deployment"
)

// The deterministic half of the surface is a projection of the daemon's tool
// Registry (ADR 0023). These tests drive the real protocol and assert on what
// the client receives: which of the daemon's Tools reach the listing, that a
// document written through one capability reads back through another, that the
// caller's Role is enforced here at the Channel, and that every call is
// attributed in the audit log.

// knowledgeTools is the deterministic surface this slice carries: the
// organization's CONTEXT, which in a Toolbox is pulled by the caller because
// Argus has no system prompt to push it into.
var knowledgeTools = []string{"list_context", "read_context", "write_context"}

// skillTools is the organization's security workflow on the same surface, for
// an agent that goes looking for it by name. The same catalog also reaches a
// client through the prompts surface (skills_test.go).
var skillTools = []string{"list_skills", "read_skill", "read_skill_file"}

// deterministicSurface is every Tool the Registry admits, in the order a client
// reads them out of tools/list — by name, which is the stable order the
// Registry projects. Each slice of the Toolbox work contributes its own names
// to it — the knowledge above, the skills here, the scanners in
// scanners_test.go — so that the listing is asserted exactly, in one place,
// against the whole of what was admitted.
func deterministicSurface() []string {
	return slices.Sorted(slices.Values(slices.Concat(knowledgeTools, skillTools, scannerTools)))
}

// callerOwnFileTools are the Tools the daemon registers for its own agent loop
// that the calling agent already has, and better. They are never admitted:
// routing them through Argus makes the client pay for the same content twice in
// its own context (ADR 0023).
var callerOwnFileTools = []string{"read_file", "grep", "list_files"}

func TestToolsList_ToolboxServesTheKnowledgeTools(t *testing.T) {
	s, _ := toolboxServer(t, auth.RoleAnalyst)
	names := listedTools(t, s)
	for _, want := range knowledgeTools {
		if !slices.Contains(names, want) {
			t.Errorf("a Toolbox must advertise %q — the knowledge needs no Provider; got %v", want, names)
		}
	}
}

func TestToolsList_AdmitsNothingByDefault(t *testing.T) {
	// The surface is a filtered projection of the Registry, and the filter is an
	// explicit decision per Tool. The daemon registers a dozen-odd Tools for its
	// own agent loop; exactly the ones somebody admitted come out here, so a Tool
	// added later cannot arrive on the surface merely by being registered.
	s, _ := toolboxServer(t, auth.RoleAnalyst)
	if names, want := listedTools(t, s), deterministicSurface(); !slices.Equal(names, want) {
		t.Errorf("a Toolbox's tool listing = %v, want exactly the admitted Tools %v", names, want)
	}
}

func TestToolsList_NeverOffersTheCallersOwnFileTools(t *testing.T) {
	for _, tc := range bothShapes(t) {
		t.Run(tc.name, func(t *testing.T) {
			names := listedTools(t, tc.server)
			for _, unwanted := range callerOwnFileTools {
				if slices.Contains(names, unwanted) {
					t.Errorf("%q must never be offered — the calling agent has it already and better; got %v", unwanted, names)
				}
			}
		})
	}
}

func TestToolsList_ColleagueServesTheDeterministicSurfaceToo(t *testing.T) {
	// The Toolbox is the floor the Colleague stands on: every deterministic tool
	// is present in both shapes, alongside review and consult.
	s, _ := reviewServer(t, &scriptedProvider{responses: textAnswer("ok")}, auth.RoleAnalyst)
	names := listedTools(t, s)
	for _, want := range knowledgeTools {
		if !slices.Contains(names, want) {
			t.Errorf("a Colleague must advertise %q as well; got %v", want, names)
		}
	}
}

func TestToolCall_ContextWrittenThroughTheSurfaceReadsBackThroughIt(t *testing.T) {
	// State is verified the way a client would: written through one capability,
	// found through a second and read through a third. Nothing inspects storage.
	s, _ := toolboxServer(t, auth.RoleAnalyst)

	res := callToolWith(t, s, "write_context", `{"name":"auth-conventions","content":"Auth uses short-lived JWTs."}`)
	if res.IsError {
		t.Fatalf("write_context must succeed for an analyst: %s", toolText(res))
	}

	if listing := toolText(callToolWith(t, s, "list_context", `{}`)); !strings.Contains(listing, "auth-conventions") {
		t.Errorf("list_context = %q, want the document just written", listing)
	}

	body := toolText(callToolWith(t, s, "read_context", `{"name":"auth-conventions"}`))
	if !strings.Contains(body, "short-lived JWTs") {
		t.Errorf("read_context = %q, want the content written through the surface", body)
	}
}

func TestToolCall_ViewerIsRefusedOnWriteContextAndPermittedOnTheReads(t *testing.T) {
	// The read-only Role means the same thing on every surface. Enforcement is
	// here at the Channel, the way review's is.
	s, auditPath := toolboxServer(t, auth.RoleViewer)
	seedOrgKnowledge(t, s)

	res := callToolWith(t, s, "write_context", `{"name":"notes","content":"anything"}`)
	if !res.IsError {
		t.Fatal("a viewer must be refused on write_context")
	}
	if text := strings.ToLower(toolText(res)); !strings.Contains(text, "read-only") && !strings.Contains(text, "permission denied") {
		t.Errorf("the refusal must say the Role is the reason: %q", toolText(res))
	}
	if e := findEvent(t, auditPath, "mcp_tool_denied"); e == nil {
		t.Error("expected an mcp_tool_denied audit event")
	}

	// The reads are still the viewer's to make — and they show the refused write
	// never happened.
	listing := callToolWith(t, s, "list_context", `{}`)
	if listing.IsError {
		t.Fatalf("a viewer must be permitted on list_context: %s", toolText(listing))
	}
	if strings.Contains(toolText(listing), "notes") {
		t.Errorf("the refused write must not have happened; list_context = %q", toolText(listing))
	}
	read := callToolWith(t, s, "read_context", `{"name":"architecture"}`)
	if read.IsError {
		t.Fatalf("a viewer must be permitted on read_context: %s", toolText(read))
	}
	if !strings.Contains(toolText(read), "Monolith on AWS") {
		t.Errorf("read_context = %q, want the seeded document's body", toolText(read))
	}
}

func TestToolCall_ViewerIsRefusedOnAnythingNotDeclaredAViewerRead(t *testing.T) {
	// The Role policy is stated as the reads a viewer may make, so a capability
	// admitted onto the surface later is refused to a read-only caller until
	// somebody decides otherwise. Proven through the protocol: every tool this
	// shape serves either answers a viewer or refuses them, and the refusals are
	// exactly the capabilities not named as viewer reads.
	s, _ := toolboxServer(t, auth.RoleViewer)
	seedOrgKnowledge(t, s)

	for _, name := range listedTools(t, s) {
		res := callToolWith(t, s, name, `{}`)
		refused := res.IsError && strings.Contains(toolText(res), "permission denied")
		if want := !slices.Contains(viewerReads, name); refused != want {
			t.Errorf("viewer refused on %q = %v, want %v (%s)", name, refused, want, toolText(res))
		}
	}
}

func TestToolCall_ToolboxCallIsAuditedAndAttributed(t *testing.T) {
	s, auditPath := toolboxServer(t, auth.RoleAnalyst)
	callToolWith(t, s, "list_context", `{}`)

	e := findEvent(t, auditPath, "mcp_tool_call")
	if e == nil {
		t.Fatal("expected an mcp_tool_call audit event")
	}
	if e.Data["tool"] != "list_context" {
		t.Errorf("audit tool = %v, want list_context", e.Data["tool"])
	}
	// Attributed to the Principal the bearer token resolved to.
	if e.Data["principal"] != "davide" {
		t.Errorf("audit principal = %v, want the Person the bearer token resolved to", e.Data["principal"])
	}
}

// shapedCase is one Deployment shape's server, for assertions that must hold in
// both extents of the surface.
type shapedCase struct {
	name   string
	server *Server
}

// bothShapes builds one server per Deployment shape.
func bothShapes(t *testing.T) []shapedCase {
	t.Helper()
	toolbox, _ := shapedServer(t, deployment.Toolbox, nil, auth.RoleAnalyst)
	colleague, _ := shapedServer(t, deployment.Colleague, &scriptedProvider{responses: textAnswer("ok")}, auth.RoleAnalyst)
	return []shapedCase{{"toolbox", toolbox}, {"colleague", colleague}}
}

// callToolWith posts a tools/call for name with the given raw JSON arguments
// and parses the CallToolResult.
func callToolWith(t *testing.T, s *Server, name, args string) toolCallResult {
	t.Helper()
	return callResult(t, callToolRaw(t, s, name, args))
}

// callToolRaw posts a tools/call for name with the given raw JSON arguments and
// returns the response body untouched, for the tests that inspect the JSON-RPC
// envelope rather than the tool result.
func callToolRaw(t *testing.T, s *Server, name, args string) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 9, "method": "tools/call",
		"params": map[string]any{"name": name, "arguments": json.RawMessage(args)},
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := post(t, s, testToken, string(body))
	if rec.Code != 200 {
		t.Fatalf("tools/call %s code = %d, want 200", name, rec.Code)
	}
	return rec.Body.Bytes()
}

// toolText is the text a calling AI reads out of a tool result.
func toolText(res toolCallResult) string {
	var b strings.Builder
	for _, c := range res.Content {
		b.WriteString(c.Text)
	}
	return b.String()
}
