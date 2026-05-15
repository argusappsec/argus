package soul_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/redcarbon-dev/argus/pkg/soul"
)

func TestParse_FrontmatterAndBody(t *testing.T) {
	raw := `---
company: RedCarbon
industry: cybersecurity
compliance:
  - SOC2
  - ISO27001
risk_tolerance: low
escalation: ciso@redcarbon.ai
monitored_repos:
  - github.com/redcarbon-dev/argus
  - github.com/redcarbon-dev/rc-guest-portal
---
You are the security agent for RedCarbon. Tone: technical, terse.
Always cite CWE/OWASP IDs. Prioritize findings by real-world impact.
`
	s, err := soul.ParseBytes([]byte(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if s.Company != "RedCarbon" {
		t.Errorf("company = %q", s.Company)
	}
	if s.Industry != "cybersecurity" {
		t.Errorf("industry = %q", s.Industry)
	}
	if len(s.Compliance) != 2 || s.Compliance[0] != "SOC2" {
		t.Errorf("compliance = %v", s.Compliance)
	}
	if s.RiskTolerance != "low" {
		t.Errorf("risk_tolerance = %q", s.RiskTolerance)
	}
	if s.Escalation != "ciso@redcarbon.ai" {
		t.Errorf("escalation = %q", s.Escalation)
	}
	if len(s.MonitoredRepos) != 2 {
		t.Errorf("monitored_repos = %v", s.MonitoredRepos)
	}
	if !strings.Contains(s.Persona, "security agent for RedCarbon") {
		t.Errorf("persona missing: %q", s.Persona)
	}
}

func TestParse_NoFrontmatter(t *testing.T) {
	raw := `Just a persona body without frontmatter.`
	s, err := soul.ParseBytes([]byte(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if s.Company != "" {
		t.Errorf("company should be empty: %q", s.Company)
	}
	if !strings.Contains(s.Persona, "persona body") {
		t.Errorf("persona missing: %q", s.Persona)
	}
}

func TestLoad_MissingFileReturnsNil(t *testing.T) {
	s, err := soul.Load(filepath.Join(t.TempDir(), "nope.md"))
	if err != nil {
		t.Fatalf("missing file should not error: %v", err)
	}
	if s != nil {
		t.Errorf("missing file should yield nil Soul, got %+v", s)
	}
}

func TestWriteAndLoad_Roundtrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "SOUL.md")
	in := &soul.Soul{
		Company:        "Acme",
		Industry:       "saas",
		Compliance:     []string{"SOC2"},
		RiskTolerance:  "medium",
		Escalation:     "sec@acme.io",
		MonitoredRepos: []string{"github.com/acme/web"},
		Persona:        "You are Acme's security copilot.",
	}
	if err := soul.Write(path, in); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := soul.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got == nil {
		t.Fatal("got nil after write+load")
	}
	if got.Company != in.Company {
		t.Errorf("company = %q, want %q", got.Company, in.Company)
	}
	if got.Persona != in.Persona {
		t.Errorf("persona = %q, want %q", got.Persona, in.Persona)
	}
	if len(got.Compliance) != 1 || got.Compliance[0] != "SOC2" {
		t.Errorf("compliance lost: %v", got.Compliance)
	}
}

func TestSystemPrompt_IncludesIdentityAndPersona(t *testing.T) {
	s := &soul.Soul{
		Company: "Acme",
		Persona: "You are technical and terse.",
	}
	prompt := s.SystemPrompt()
	if !strings.Contains(prompt, "Acme") {
		t.Errorf("system prompt missing company: %q", prompt)
	}
	if !strings.Contains(prompt, "technical and terse") {
		t.Errorf("system prompt missing persona: %q", prompt)
	}
}
