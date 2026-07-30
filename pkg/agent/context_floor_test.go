package agent_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/argusappsec/argus/pkg/agent"
	"github.com/argusappsec/argus/pkg/provider"
	"github.com/argusappsec/argus/pkg/security"
	"github.com/argusappsec/argus/pkg/session"
	"github.com/argusappsec/argus/pkg/skill"
	"github.com/argusappsec/argus/pkg/soul"
	"github.com/argusappsec/argus/pkg/tool"
)

// This file measures how much context one turn costs before the conversation
// has said anything, and guards that figure from both directions: the byte
// ceilings below catch silent growth, and the declaration count catches a tool
// that silently stopped reaching the model — which would make the measurement
// look *better* while breaking the agent.
//
// Why it is worth measuring at all: SOUL and MEMORY enter the system prompt in
// full on EVERY call, and the tool declarations ride along on every call too. A
// model whose context window cannot hold that has no room left for the scanner
// output and file contents a real Review accumulates, and it fails on the first
// turn. So docs/guide/llm-providers.md publishes a context-window floor that
// operators size a model against, and these tests are what keep it true.
//
// Why bytes and not tokens: converting needs a tokenizer, which differs per
// model family and which Argus deliberately does not carry. Bytes are exact and
// dependency-free, and the published floor declares its own bytes-per-token
// ratio so a reader can redo the arithmetic with whatever ratio their model
// actually uses.

// Ceilings on Argus's own fixed per-call overhead, in bytes.
//
// These are growth guards, not targets. Each sits roughly 50% above the figure
// measured when it was set, so an ordinary edit — a clearer tool description, a
// new severity-guidance sentence — passes, while a doubling trips. Raising one
// is a legitimate fix, but only *after* re-deriving the floor published in
// docs/guide/llm-providers.md from the new measurement: the number in the guide
// is what an operator sizes a model against.
const (
	// toolDeclCeiling bounds the tool declarations: every tool's name,
	// description and JSON Schema, for the whole registry a Session exposes
	// plus the two control tools the loop handles itself. Measured at 7,765 B
	// on 2026-07-30.
	toolDeclCeiling = 11500

	// systemPromptCeiling bounds the assembled system prompt — the persona
	// line, the rendered SOUL, and the MEMORY section — for the fixture below.
	// It bounds Argus's *scaffolding*, since the fixture's own prose is fixed:
	// an operator's real SOUL and MEMORY are their own bytes on top. Measured
	// at 1,188 B on 2026-07-30.
	systemPromptCeiling = 1800

	// declaredToolCount is how many declarations a Review turn carries: the
	// fullRegistry below plus add_finding and finalize_report. Pinned because
	// docs/guide/llm-providers.md quotes it alongside the byte figure, so a
	// change here dates the guide.
	declaredToolCount = 17
)

// TestFixedContextOverheadStaysWithinItsCeiling measures the system prompt and
// tool declarations Argus puts on the wire at the start of a Review with a full
// Tool registry, and fails if either has outgrown its ceiling.
func TestFixedContextOverheadStaysWithinItsCeiling(t *testing.T) {
	captured := captureFirstRequest(t)

	systemBytes := len(captured.System)
	// Measured on the provider-agnostic value the agent hands EVERY Provider,
	// not on one protocol's envelope: pkg/agent does not know a wire format,
	// and encoding this here would make the guard track a Provider's framing
	// rather than Argus's own prompt. A real protocol envelope adds a few
	// percent on top; the floor in the guide carries headroom for it.
	declJSON, err := json.Marshal(captured.Tools)
	if err != nil {
		t.Fatalf("marshal tool declarations: %v", err)
	}
	declBytes := len(declJSON)

	// Reported unconditionally: `go test -v ./pkg/agent/` is how a maintainer
	// re-derives the published floor without reverse-engineering a diff.
	t.Logf("fixed per-call context overhead: system prompt %d B, %d tool declarations %d B, total %d B",
		systemBytes, len(captured.Tools), declBytes, systemBytes+declBytes)

	assertWithinCeiling(t, "the tool declaration block", declBytes, toolDeclCeiling,
		"a tool was added, or a tool's description or JSON Schema grew — look in pkg/tool, pkg/security, or controlToolDecls in pkg/agent/agent.go")
	assertWithinCeiling(t, "the assembled system prompt", systemBytes, systemPromptCeiling,
		"the persona line, soul.SystemPrompt's rendered guidance, or the MEMORY section grew — look in composeSystemPrompt in pkg/agent/agent.go, or pkg/soul")
}

// TestEveryRegisteredToolIsDeclaredToTheModel guards the other direction: that
// the agent forwards the whole registry, plus the control tools it handles
// itself, rather than a subset. A tool the model is never told about is a tool
// it can never call.
func TestEveryRegisteredToolIsDeclaredToTheModel(t *testing.T) {
	registry := fullRegistry(t)
	captured := captureFirstRequestWith(t, registry)

	declared := make(map[string]bool, len(captured.Tools))
	for _, d := range captured.Tools {
		declared[d.Name] = true
	}

	// The registry's own tools, read from the registry rather than re-listed
	// here: a hand-copied list would only assert that two copies agree.
	for _, d := range registry.Decls() {
		if !declared[d.Name] {
			t.Errorf("registered tool %q was not declared to the model", d.Name)
		}
	}
	// The control tools are the loop's, not the registry's: without them the
	// model has no way to file a finding or end the run.
	for _, name := range []string{"add_finding", "finalize_report"} {
		if !declared[name] {
			t.Errorf("control tool %q was not declared to the model", name)
		}
	}

	if len(captured.Tools) != declaredToolCount {
		t.Errorf("a Review turn carries %d tool declarations, want %d; "+
			"if this change is intended, update declaredToolCount and the figure "+
			"quoted in docs/guide/llm-providers.md", len(captured.Tools), declaredToolCount)
	}
}

// captureFirstRequest runs one agent turn against a full Tool registry and
// returns the provider.Request the agent built for it.
func captureFirstRequest(t *testing.T) provider.Request {
	t.Helper()
	return captureFirstRequestWith(t, fullRegistry(t))
}

// captureFirstRequestWith is captureFirstRequest against a caller-owned
// registry, for a test that needs to compare the request against it.
//
// The observation point is the Provider interface — the same seam every other
// test in this package uses — so what is measured is what a Provider is
// actually handed, with no visibility into how the agent assembled it. The
// scripted response carries text and no tool call, which is the agent's natural
// pause point, so the run ends after exactly one turn.
func captureFirstRequestWith(t *testing.T, registry *tool.Registry) provider.Request {
	t.Helper()

	op := &observingProvider{responses: []provider.Response{{Text: "Nothing to review."}}}
	ag := agent.New(agent.Options{
		Provider:    op,
		Tools:       registry,
		Soul:        fixtureSoul(),
		Memory:      fixtureMemory,
		PersonaName: "Argus",
	})
	if _, err := ag.Run(context.Background(), agent.Target{Repo: "github.com/acme/payments-api", SHA: "deadbeef"}); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(op.requests) != 1 {
		t.Fatalf("provider was called %d times, want exactly 1", len(op.requests))
	}
	return op.requests[0]
}

// fullRegistry assembles the tool set a Session exposes. It mirrors
// buildRegistry in pkg/daemon/session.go, and is built here rather than
// imported because pkg/daemon imports pkg/agent.
//
// The mirror is maintained by hand: nothing here notices a tool added to
// buildRegistry alone. What notices is declaredToolCount going stale against
// the guide the next time this file is touched, which is the honest bound on
// what a test in this package can guarantee about another one's registry.
//
// A second gap the published floor accounts for rather than measures: the
// GitHub channel layers two more request-scoped tools (suppress_finding,
// rescope_review) onto a per-run copy of the registry for a PR comment turn, so
// the widest real turn declares two more than this.
//
// Nothing is executed, only declared, so the tools' dependencies can be empty:
// a Session with no checkout, directories that need not exist, and a nil
// RepoCloner (which start_review_github explicitly supports).
func fullRegistry(t *testing.T) *tool.Registry {
	t.Helper()

	home := t.TempDir()
	contextDir := filepath.Join(home, "context")
	skills := skill.NewCatalog(skill.Builtin(), filepath.Join(home, "skills"))
	sess := session.New()

	reg := tool.NewRegistry()
	reg.Register(tool.NewListFiles(sess))
	reg.Register(tool.NewReadFile(sess))
	reg.Register(tool.NewGrep(sess))
	reg.Register(tool.NewListContext(contextDir))
	reg.Register(tool.NewReadContext(contextDir))
	reg.Register(tool.NewWriteContext(contextDir))
	reg.Register(tool.NewStartReviewLocal(sess))
	reg.Register(tool.NewStartReviewGitHub(sess, nil))
	reg.Register(tool.NewPRDiff(sess))
	reg.Register(security.NewSemgrep(sess, security.ExecRunner{}))
	reg.Register(security.NewGitleaks(sess, security.ExecRunner{}))
	reg.Register(security.NewOSVScanner(sess, security.ExecRunner{}))
	reg.Register(tool.NewListSkills(skills))
	reg.Register(tool.NewReadSkill(skills))
	reg.Register(tool.NewReadSkillFile(skills))
	return reg
}

// fixtureSoul is a SOUL with every structured field populated and its free
// prose kept short. Filling every field is the conservative choice for a floor
// — each one renders a guidance sentence into the prompt — while the short
// prose keeps the measurement about Argus's scaffolding rather than about how
// much an author wrote.
func fixtureSoul() *soul.Soul {
	return &soul.Soul{
		Company:         "Acme",
		Industry:        "payments",
		DataSensitivity: "pci",
		PrimaryStack:    []string{"Go", "TypeScript"},
		Infra:           []string{"AWS", "Kubernetes"},
		SecretStorage:   "HashiCorp Vault",
		Compliance:      []string{"PCI-DSS", "SOC 2"},
		RiskTolerance:   "low",
		Language:        "english",
		SeverityRules:   []string{"Any leak of cardholder data is Critical."},
		Persona:         "## Mission\nReview code for the payments platform.\n\n## Conduct\nBe terse and cite files.",
	}
}

// fixtureMemory stands in for MEMORY.md: short, because its length is the
// operator's and not Argus's, but non-empty so the section Argus wraps it in is
// part of the measurement.
const fixtureMemory = "- The team accepts the `internal/testdata` fixtures as intentional test secrets.\n"

// assertWithinCeiling fails with a message a maintainer can act on. A bare
// "12345 > 12000" says a limit moved but not what moved it, what it means, or
// which of the two legitimate fixes applies — so whatGrew names the likely
// cause and where to look, and the body carries the rest.
func assertWithinCeiling(t *testing.T, what string, got, ceiling int, whatGrew string) {
	t.Helper()
	if got <= ceiling {
		return
	}
	t.Errorf(`%s now measures %d B, over its %d B growth guard (+%d B, %+.0f%%).

This is not a bug by itself — it is a signal that Argus's fixed per-call
context cost has grown. Most likely %s.

Two fixes, in this order:
  1. If the growth is unintended, shrink it. Every byte here is spent on
     EVERY model call of EVERY Review, before the conversation says anything.
  2. If the growth is intended, re-derive the context-window floor in
     docs/guide/llm-providers.md from the total this test logs (run with -v),
     then raise this constant to about 1.5x the new measurement. Raising the
     constant without updating the guide leaves operators sizing their model
     against a number Argus no longer honours.`,
		what, got, ceiling, got-ceiling,
		100*float64(got-ceiling)/float64(ceiling), whatGrew)
}
