package mcp

import (
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/argusappsec/argus/pkg/auth"
	"github.com/argusappsec/argus/pkg/deployment"
)

// The Skill catalog reaches an external AI two ways, and these tests drive the
// real protocol for both: as Tools, for an agent that goes looking by name, and
// as MCP prompts, for a user who does not know Argus's tool names and should
// not have to. What they assert is that the two are one catalog with one set of
// bodies — a Skill written once is the same Skill whichever way it is fetched.

// listedPrompts returns what a client sees in prompts/list.
func listedPrompts(t *testing.T, s *Server) promptsListResult {
	t.Helper()
	var resp struct {
		Result promptsListResult `json:"result"`
		Error  *rpcError         `json:"error"`
	}
	rec := post(t, s, testToken, `{"jsonrpc":"2.0","id":1,"method":"prompts/list"}`)
	if rec.Code != 200 {
		t.Fatalf("prompts/list code = %d, want 200", rec.Code)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse prompts/list: %v\nbody: %s", err, rec.Body.String())
	}
	if resp.Error != nil {
		t.Fatalf("unexpected JSON-RPC error: %+v", resp.Error)
	}
	return resp.Result
}

// getPrompt retrieves one prompt by name and parses the GetPromptResult.
func getPrompt(t *testing.T, s *Server, name string) getPromptResult {
	t.Helper()
	var resp struct {
		Result getPromptResult `json:"result"`
		Error  *rpcError       `json:"error"`
	}
	body := `{"jsonrpc":"2.0","id":2,"method":"prompts/get","params":{"name":"` + name + `"}}`
	rec := post(t, s, testToken, body)
	if rec.Code != 200 {
		t.Fatalf("prompts/get code = %d, want 200", rec.Code)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse prompts/get: %v\nbody: %s", err, rec.Body.String())
	}
	if resp.Error != nil {
		t.Fatalf("unexpected JSON-RPC error: %+v", resp.Error)
	}
	return resp.Result
}

// findPrompt returns the offered prompt with the given name, or nil.
func findPrompt(res promptsListResult, name string) *promptDecl {
	for i := range res.Prompts {
		if res.Prompts[i].Name == name {
			return &res.Prompts[i]
		}
	}
	return nil
}

// seedUserSkill writes a user-curated Skill bundle under the daemon home. A
// name a built-in already owns is the whole-bundle override.
func seedUserSkill(t *testing.T, s *Server, name, description, body string) {
	t.Helper()
	mustWrite(t, filepath.Join(s.dc.Home, "skills", name, "SKILL.md"),
		"---\nname: "+name+"\ndescription: "+description+"\n---\n"+body)
}

func TestToolCall_ToolboxServesTheSkills(t *testing.T) {
	// An external AI connected to a Provider-less daemon can discover the
	// organization's security workflow and read it, bundled files included.
	s, _ := toolboxServer(t, auth.RoleAnalyst)

	names := listedTools(t, s)
	for _, want := range skillTools {
		if !slices.Contains(names, want) {
			t.Errorf("a Toolbox must advertise %q — the Skills need no Provider; got %v", want, names)
		}
	}

	listing := toolText(callToolWith(t, s, "list_skills", `{}`))
	if !strings.Contains(listing, "threat-modeling") {
		t.Errorf("list_skills = %q, want the built-in catalog", listing)
	}

	body := toolText(callToolWith(t, s, "read_skill", `{"name":"threat-modeling"}`))
	if !strings.Contains(body, "STRIDE") {
		t.Errorf("read_skill = %q, want the skill's body", body)
	}

	file := toolText(callToolWith(t, s, "read_skill_file", `{"skill":"threat-modeling","path":"stride-template.md"}`))
	if !strings.Contains(file, "STRIDE Threat Model") {
		t.Errorf("read_skill_file = %q, want the bundled template", file)
	}
}

func TestInitialize_AdvertisesThePromptsCapability(t *testing.T) {
	// A client learns from the handshake that Argus offers prompts, so the
	// organization's workflow reaches the user's own prompt menu without them
	// knowing a single tool name. The Skills need no Provider, so both shapes
	// advertise it.
	for _, tc := range bothShapes(t) {
		t.Run(tc.name, func(t *testing.T) {
			if caps := handshakeCapabilities(t, tc.server); caps["prompts"] == nil {
				t.Errorf("initialize must advertise the prompts capability, got %+v", caps)
			}
		})
	}
}

func TestPromptsList_OffersTheSkillCatalog(t *testing.T) {
	// The organization's security workflow shows up in the caller's own prompt
	// menu: one prompt per Skill, carrying the description that tells the user
	// when to reach for it.
	s, auditPath := toolboxServer(t, auth.RoleAnalyst)

	got := listedPrompts(t, s)
	p := findPrompt(got, "threat-modeling")
	if p == nil {
		t.Fatalf("prompts/list must offer the built-in Skills, got %+v", got.Prompts)
	}
	if !strings.Contains(p.Description, "STRIDE") {
		t.Errorf("prompt description = %q, want the Skill's own description", p.Description)
	}
	if got.Prompts == nil {
		t.Error("prompts must serialize as [], not null")
	}

	if e := findEvent(t, auditPath, "mcp_prompts_list"); e == nil || e.Data["principal"] != "davide" {
		t.Errorf("expected an mcp_prompts_list event attributed to davide, got %+v", e)
	}
}

func TestPromptsList_IsTheSameCatalogTheSkillToolsRead(t *testing.T) {
	// Same catalog, no second store: every name the prompts surface offers is a
	// name list_skills reports, and vice versa.
	s, _ := toolboxServer(t, auth.RoleAnalyst)
	seedUserSkill(t, s, "house-style", "Our own review checklist.", "# House style\nRead CONTEXT first.")

	listing := toolText(callToolWith(t, s, "list_skills", `{}`))
	for _, p := range listedPrompts(t, s).Prompts {
		if !strings.Contains(listing, p.Name) {
			t.Errorf("prompt %q is offered but list_skills does not report it: %q", p.Name, listing)
		}
	}
	for _, line := range strings.Split(listing, "\n") {
		name, _, _ := strings.Cut(line, " — ")
		if findPrompt(listedPrompts(t, s), name) == nil {
			t.Errorf("list_skills reports %q but the prompts surface does not offer it", name)
		}
	}
}

func TestPromptsGet_ReturnsTheSkillBodyTheSkillToolsReturn(t *testing.T) {
	// Retrieval hands the client the Skill's own body — byte for byte the one
	// read_skill returns, because there is one store behind both surfaces.
	s, auditPath := toolboxServer(t, auth.RoleAnalyst)

	got := getPrompt(t, s, "threat-modeling")
	if len(got.Messages) != 1 {
		t.Fatalf("prompts/get returned %d messages, want the Skill body as one", len(got.Messages))
	}
	m := got.Messages[0]
	if m.Role != "user" {
		t.Errorf("message role = %q, want user — a Skill is instructions for whoever reasons", m.Role)
	}
	if m.Content.Type != "text" {
		t.Errorf("content type = %q, want text", m.Content.Type)
	}
	if want := toolText(callToolWith(t, s, "read_skill", `{"name":"threat-modeling"}`)); m.Content.Text != want {
		t.Errorf("prompts/get body and read_skill body differ:\n prompt = %q\n tool   = %q", m.Content.Text, want)
	}
	if !strings.Contains(got.Description, "STRIDE") {
		t.Errorf("prompts/get description = %q, want the Skill's own description", got.Description)
	}

	if e := findEvent(t, auditPath, "mcp_prompt_get"); e == nil || e.Data["prompt"] != "threat-modeling" {
		t.Errorf("expected an mcp_prompt_get event naming the Skill, got %+v", e)
	}
}

func TestPrompts_UserCuratedSkillsAppearAndOverrideWholeBundle(t *testing.T) {
	// Both sources reach the prompts surface, and the override rule is the one
	// the daemon already applies: a user directory claiming a built-in's name
	// wins the entire bundle — body and supporting files together, never a mix.
	s, _ := toolboxServer(t, auth.RoleAnalyst)
	seedUserSkill(t, s, "house-style", "Our own review checklist.", "# House style\nRead CONTEXT first.")
	seedUserSkill(t, s, "threat-modeling", "Our threat model, our way.", "# Our STRIDE\nStart from the tenancy boundary.")

	own := findPrompt(listedPrompts(t, s), "house-style")
	if own == nil {
		t.Fatalf("a user-curated Skill must be offered as a prompt, got %+v", listedPrompts(t, s).Prompts)
	}
	if own.Description != "Our own review checklist." {
		t.Errorf("prompt description = %q, want the user Skill's own", own.Description)
	}

	overridden := findPrompt(listedPrompts(t, s), "threat-modeling")
	if overridden == nil || overridden.Description != "Our threat model, our way." {
		t.Errorf("the user bundle must claim the built-in's name in the listing, got %+v", overridden)
	}
	if body := getPrompt(t, s, "threat-modeling").Messages[0].Content.Text; !strings.Contains(body, "tenancy boundary") {
		t.Errorf("prompts/get = %q, want the overriding bundle's body", body)
	}

	// Whole-bundle: the built-in's supporting file does not survive its name
	// being claimed, so a body and its files never cross sources.
	res := callToolWith(t, s, "read_skill_file", `{"skill":"threat-modeling","path":"stride-template.md"}`)
	if !res.IsError {
		t.Errorf("the built-in's file must not resurface under an overriding bundle, got %q", toolText(res))
	}
}

func TestPromptsGet_UnknownPromptIsRejected(t *testing.T) {
	s, _ := toolboxServer(t, auth.RoleAnalyst)
	var resp rpcResponse
	body := `{"jsonrpc":"2.0","id":4,"method":"prompts/get","params":{"name":"no-such-skill"}}`
	if err := json.Unmarshal(post(t, s, testToken, body).Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Error == nil || resp.Error.Code != codeInvalidParams {
		t.Fatalf("error = %+v, want invalid-params (%d) for a prompt Argus does not have", resp.Error, codeInvalidParams)
	}
}

func TestPrompts_NonReadingRoleSeesNothingAndCannotRetrieve(t *testing.T) {
	// The prompts surface is a read of the organization's knowledge, so it
	// respects the caller's Role the way the resource surface does.
	s, auditPath := shapedServer(t, deployment.Toolbox, nil, auth.RoleMirrorRead)

	if got := listedPrompts(t, s); len(got.Prompts) != 0 {
		t.Errorf("a non-reading role must see no prompts, got %+v", got.Prompts)
	}
	if findEvent(t, auditPath, "mcp_prompts_list_denied") == nil {
		t.Error("expected an mcp_prompts_list_denied audit event")
	}

	var resp rpcResponse
	body := `{"jsonrpc":"2.0","id":5,"method":"prompts/get","params":{"name":"threat-modeling"}}`
	if err := json.Unmarshal(post(t, s, testToken, body).Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Error == nil || resp.Error.Code != codeForbidden {
		t.Fatalf("a non-reading role's retrieval must be forbidden (%d), got %+v", codeForbidden, resp.Error)
	}
	if findEvent(t, auditPath, "mcp_prompt_get_denied") == nil {
		t.Error("expected an mcp_prompt_get_denied audit event")
	}
}

func TestPrompts_ViewerMayListAndRetrieve(t *testing.T) {
	// A viewer reads the Skills on both surfaces: the read-only Role means the
	// same thing whichever way the catalog is reached.
	s, _ := toolboxServer(t, auth.RoleViewer)

	if findPrompt(listedPrompts(t, s), "pr-quick-check") == nil {
		t.Error("a viewer must see the Skill catalog in the prompt menu")
	}
	if body := getPrompt(t, s, "pr-quick-check").Messages[0].Content.Text; body == "" {
		t.Error("a viewer must be able to retrieve a Skill body")
	}
	if res := callToolWith(t, s, "list_skills", `{}`); res.IsError {
		t.Errorf("a viewer must be permitted on list_skills: %s", toolText(res))
	}
}

func TestToolCall_SkillFileStaysInsideItsOwnBundle(t *testing.T) {
	// A supporting file is addressed relative to its own Skill's directory and
	// nothing else is reachable through it, exactly as before this surface
	// existed.
	s, _ := toolboxServer(t, auth.RoleAnalyst)

	for _, path := range []string{"../pr-quick-check/SKILL.md", "/etc/passwd"} {
		res := callToolWith(t, s, "read_skill_file", `{"skill":"threat-modeling","path":"`+path+`"}`)
		if !res.IsError {
			t.Errorf("read_skill_file(%q) must be refused, got %q", path, toolText(res))
		}
	}
}
