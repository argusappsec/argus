package mcp

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/argusappsec/argus/pkg/auth"
	"github.com/argusappsec/argus/pkg/memory"
	"github.com/argusappsec/argus/pkg/provider"
)

// MEMORY has one mechanism and two callers (ADR 0023): the external AI over
// MCP, and Argus's own curator in a Colleague. These tests drive the real
// protocol against the first caller and assert on what the client receives —
// that what was saved comes back through a different capability, that the
// ceiling tells the caller rather than dropping anything, that a viewer is
// refused, and that an accepted false positive stays advisory.

// memoryTools is the deterministic surface this slice carries: the two writes
// that make Argus remember without a Provider to run a curator with.
var memoryTools = []string{"mark_false_positive", "save_memory"}

// readResourceText reads one resource by URI the way a client does and returns
// its body. MEMORY is read back through the Resource surface rather than off
// disk, so what the test sees is what the external AI sees.
func readResourceText(t *testing.T, s *Server, uri string) string {
	t.Helper()
	rec := post(t, s, testToken, `{"jsonrpc":"2.0","id":4,"method":"resources/read","params":{"uri":"`+uri+`"}}`)
	if rec.Code != 200 {
		t.Fatalf("resources/read %s code = %d, want 200", uri, rec.Code)
	}
	var resp struct {
		Result readResourceResult `json:"result"`
		Error  *rpcError          `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse resources/read: %v\nbody: %s", err, rec.Body.String())
	}
	if resp.Error != nil {
		t.Fatalf("resources/read %s: unexpected JSON-RPC error: %+v", uri, resp.Error)
	}
	var b strings.Builder
	for _, c := range resp.Result.Contents {
		b.WriteString(c.Text)
	}
	return b.String()
}

// listedResources returns the resource URIs a client sees in resources/list.
func listedResources(t *testing.T, s *Server) []string {
	t.Helper()
	res := listResult(t, post(t, s, testToken, `{"jsonrpc":"2.0","id":5,"method":"resources/list"}`).Body.Bytes())
	uris := make([]string, 0, len(res.Resources))
	for _, r := range res.Resources {
		uris = append(uris, r.URI)
	}
	return uris
}

func TestToolsList_ToolboxServesTheMemoryTools(t *testing.T) {
	s, _ := toolboxServer(t, auth.RoleAnalyst)
	names := listedTools(t, s)
	for _, want := range memoryTools {
		if !slices.Contains(names, want) {
			t.Errorf("a Toolbox must advertise %q — remembering needs no Provider; got %v", want, names)
		}
	}
}

func TestToolCall_MemorySavedThroughTheSurfaceReadsBackThroughIt(t *testing.T) {
	// Written through one capability, read through another. Nothing inspects
	// storage: this is exactly what a client can see.
	s, _ := toolboxServer(t, auth.RoleAnalyst)

	res := callToolWith(t, s, "save_memory", `{"content":"This team deploys on Fridays and wants HIGH findings first."}`)
	if res.IsError {
		t.Fatalf("save_memory must succeed for an analyst: %s", toolText(res))
	}

	if body := readResourceText(t, s, memoryURI); !strings.Contains(body, "deploys on Fridays") {
		t.Errorf("argus://memory = %q, want what was just saved through the surface", body)
	}
}

func TestToolCall_MemoryPastTheCeilingSavesAnywayAndSaysSo(t *testing.T) {
	// The one place the Toolbox is worse than the Colleague, paid for rather
	// than ignored: past the ceiling the write still lands in full, and the
	// caller is told to migrate material to CONTEXT.
	s, _ := toolboxServer(t, auth.RoleAnalyst)

	bulky := strings.Repeat("the same long-winded convention, restated. ", memory.Ceiling/40)
	if res := callToolWith(t, s, "save_memory", `{"content":"`+bulky+`"}`); res.IsError {
		t.Fatalf("a write past the ceiling must still succeed: %s", toolText(res))
	}

	res := callToolWith(t, s, "save_memory", `{"content":"Postgres is behind PgBouncer."}`)
	if res.IsError {
		t.Fatalf("a write past the ceiling must still succeed: %s", toolText(res))
	}
	text := toolText(res)
	if !strings.Contains(text, memory.FullSignal) {
		t.Errorf("a write past the ceiling must say MEMORY is full; got %q", text)
	}
	if !strings.Contains(text, "CONTEXT") || !strings.Contains(text, "write_context") {
		t.Errorf("the signal must name where the material should migrate to; got %q", text)
	}

	// Nothing was truncated or dropped: both writes are there in full.
	body := readResourceText(t, s, memoryURI)
	if !strings.Contains(body, "PgBouncer") {
		t.Errorf("the write past the ceiling was dropped; argus://memory = %q", body)
	}
	if strings.Count(body, "the same long-winded convention, restated.") != memory.Ceiling/40 {
		t.Error("the bulky entry was truncated; a full MEMORY tells the caller, it never edits what it was given")
	}
}

func TestToolCall_ViewerIsRefusedOnBothMemoryWrites(t *testing.T) {
	// The read-only Role means the same thing on every surface, and the refusal
	// is observable: MEMORY never came into existence.
	s, auditPath := toolboxServer(t, auth.RoleViewer)

	for _, name := range memoryTools {
		res := callToolWith(t, s, name, `{"content":"anything","rule_id":"CWE-89"}`)
		if !res.IsError {
			t.Errorf("a viewer must be refused on %s", name)
		}
		if text := strings.ToLower(toolText(res)); !strings.Contains(text, "permission denied") {
			t.Errorf("%s: the refusal must say the Role is the reason: %q", name, toolText(res))
		}
	}
	if e := findEvent(t, auditPath, "mcp_tool_denied"); e == nil {
		t.Error("expected an mcp_tool_denied audit event")
	}
	if resources := listedResources(t, s); slices.Contains(resources, memoryURI) {
		t.Error("the refused writes must not have happened; argus://memory exists")
	}
}

// rememberingProvider is a scriptedProvider that keeps the system prompt it was
// sent, which is where a later Session's MEMORY shows up.
type rememberingProvider struct {
	scriptedProvider
	systems []string
}

func (p *rememberingProvider) Generate(ctx context.Context, req provider.Request) (provider.Response, error) {
	p.systems = append(p.systems, req.System)
	return p.scriptedProvider.Generate(ctx, req)
}

// remembered is everything the provider was told about the organization across
// the turns it served.
func (p *rememberingProvider) remembered() string { return strings.Join(p.systems, "\n") }

// colleagueThatRemembers builds a Colleague whose MEMORY snapshot comes from the
// daemon's own memory mechanism, the way daemon.Build wires it — shapedServer
// stubs it empty, and a Session that never reads MEMORY could not show that a
// write reached it.
func colleagueThatRemembers(t *testing.T, prov provider.Provider) *Server {
	t.Helper()
	s, _ := reviewServer(t, prov, auth.RoleAnalyst)
	s.dc.LoadMemory = s.dc.MemoryStore().Load
	return s
}

func TestToolCall_MemorySavedOverMCPReachesTheNextSession(t *testing.T) {
	// The point of remembering: what was settled in one conversation is in the
	// next one without anybody restating it. Written through save_memory, read
	// back through consult — a Session created after the write, whose answer is
	// grounded in the organization's knowledge.
	prov := &rememberingProvider{scriptedProvider: scriptedProvider{responses: textAnswer("Fridays, then.")}}
	s := colleagueThatRemembers(t, prov)

	res := callToolWith(t, s, "save_memory", `{"content":"This team does not deploy on Fridays."}`)
	if res.IsError {
		t.Fatalf("save_memory must succeed for an analyst: %s", toolText(res))
	}

	body := `{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"consult","arguments":{"question":"when do we ship?"}}}`
	if answer := callResult(t, post(t, s, testToken, body).Body.Bytes()); answer.IsError {
		t.Fatalf("consult must answer: %s", toolText(answer))
	}
	if !strings.Contains(prov.remembered(), "does not deploy on Fridays") {
		t.Errorf("what was saved over MCP must reach the next Session's knowledge; it saw:\n%s", prov.remembered())
	}
}

func TestToolCall_FalsePositiveDoesNotMuteTheSameFindingElsewhere(t *testing.T) {
	// Advisory means the next reader re-judges: the accepted false positive is
	// in the knowledge the reviewing agent is given, and a finding carrying the
	// very same rule still comes back to the caller. Nothing on the way out
	// filters a finding because MEMORY has seen its rule before.
	prov := &rememberingProvider{scriptedProvider: scriptedProvider{responses: findingThenFinalize()}}
	s := colleagueThatRemembers(t, prov)

	res := callToolWith(t, s, "mark_false_positive", `{"rule_id":"CWE-89","file":"internal/report/query.go","reason":"allow-listed column name"}`)
	if res.IsError {
		t.Fatalf("mark_false_positive must succeed for an analyst: %s", toolText(res))
	}

	body := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"review","arguments":` +
		`{"files":[{"path":"login.go","content":"package main\n"}]}}}`
	review := callResult(t, post(t, s, testToken, body).Body.Bytes())
	if review.IsError {
		t.Fatalf("review must run: %s", toolText(review))
	}
	if !strings.Contains(toolText(review), "CWE-89") {
		t.Errorf("an accepted false positive must not mute the same rule elsewhere; review returned %s", toolText(review))
	}
	if !strings.Contains(prov.remembered(), "NOT a global mute") {
		t.Errorf("the reviewing agent must be given the acceptance as guidance to re-judge; it saw:\n%s", prov.remembered())
	}
}

func TestToolCall_FalsePositiveIsRecordedAsAdvisoryNotAMute(t *testing.T) {
	// What mark_false_positive records is guidance the next reader re-judges,
	// so the same finding in a genuinely vulnerable context elsewhere can still
	// be flagged. Pinned on what the record itself says.
	s, _ := toolboxServer(t, auth.RoleAnalyst)

	res := callToolWith(t, s, "mark_false_positive",
		`{"rule_id":"CWE-89","file":"internal/report/query.go","reason":"the identifier is an allow-listed column name"}`)
	if res.IsError {
		t.Fatalf("mark_false_positive must succeed for an analyst: %s", toolText(res))
	}
	if text := toolText(res); !strings.Contains(text, "not a global mute") && !strings.Contains(text, "NOT a global mute") {
		t.Errorf("the caller must be told the record is advisory; got %q", text)
	}

	body := readResourceText(t, s, memoryURI)
	if !strings.Contains(body, "CWE-89") || !strings.Contains(body, "internal/report/query.go") {
		t.Errorf("argus://memory = %q, want the accepted false positive", body)
	}
	if !strings.Contains(body, "allow-listed column name") {
		t.Errorf("argus://memory = %q, want the reason the developer gave", body)
	}
	if !strings.Contains(strings.ToLower(body), "not a global mute") {
		t.Errorf("the record must read as advisory to whoever loads it next; got %q", body)
	}
}
