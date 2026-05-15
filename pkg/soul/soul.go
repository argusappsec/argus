// Package soul represents the persistent identity of an Argus agent.
//
// A Soul lives on disk at ~/.argus/SOUL.md as markdown-with-frontmatter: YAML
// metadata between two `---` lines, then a free-form persona body. The agent
// loads it once at startup and injects it into every LLM call as the system
// prompt — this is how identity becomes *persistent* across sessions.
//
// The schema is intentionally narrow. Anything that drifts (today's repos,
// today's findings, last week's reasoning) belongs in MEMORY.md or
// CONTEXT/, not here.
package soul

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Soul is the agent's persistent identity.
//
// Schema rule: every field here is loaded as the LLM's system prompt on
// EVERY agent run. Token budget matters. Only put here info that's
// relevant to most reviews. Per-project deep-dive (architecture, threat
// model, known FPs) belongs in CONTEXT/ — loaded on demand.
type Soul struct {
	Company  string `yaml:"company,omitempty"`
	Industry string `yaml:"industry,omitempty"`

	// DataSensitivity is the broad category of data the software handles.
	// Drives encryption / retention / leak severity calibration.
	// Suggested values: "public", "internal", "pii", "phi", "pci", "regulated".
	DataSensitivity string `yaml:"data_sensitivity,omitempty"`

	// PrimaryStack lists the languages/runtimes the codebase predominantly
	// uses (e.g. ["Go", "Python", "TypeScript"]). Lets the agent prioritise
	// lang-specific scanners and reason about idiomatic vulnerabilities.
	PrimaryStack []string `yaml:"primary_stack,omitempty"`

	// Infra lists the platforms / orchestrators / data stores the software
	// runs on (e.g. ["AWS", "Kubernetes", "PostgreSQL"]). Drives which
	// IaC / cloud-specific rules matter.
	Infra []string `yaml:"infra,omitempty"`

	// SecretStorage describes WHERE secrets actually live in production.
	// Massive false-positive reducer: if the agent knows secrets come from
	// Vault, then `${VAULT_TOKEN}` in a manifest is a placeholder, not a leak.
	// Examples: "HashiCorp Vault", "AWS Secrets Manager", "K8s Secrets",
	// "Doppler", ".env files (dev only)".
	SecretStorage string `yaml:"secret_storage,omitempty"`

	// Compliance frameworks the company is subject to.
	Compliance []string `yaml:"compliance,omitempty"`

	// RiskTolerance: "low" | "medium" | "high".
	RiskTolerance string `yaml:"risk_tolerance,omitempty"`

	// Escalation is the security owner's email or chat handle. Cited by
	// the agent in HIGH+ findings.
	Escalation string `yaml:"escalation,omitempty"`

	// Persona is the markdown body after the frontmatter. Free-form prose
	// the human (or the bootstrap agent) wrote about tone, priorities and
	// any context that doesn't fit the structured fields.
	Persona string `yaml:"-"`
}

// Load reads a Soul from path. A missing file is not an error: it returns
// (nil, nil) so callers can default to "no soul, no system prompt".
func Load(path string) (*Soul, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("soul: read %s: %w", path, err)
	}
	return ParseBytes(data)
}

// ParseBytes parses raw markdown content. If the content does not start with
// `---\n`, the whole content is treated as the Persona body (no frontmatter).
func ParseBytes(raw []byte) (*Soul, error) {
	const sep = "---"
	s := string(raw)

	if !strings.HasPrefix(s, sep+"\n") && !strings.HasPrefix(s, sep+"\r\n") {
		return &Soul{Persona: strings.TrimSpace(s)}, nil
	}

	// Locate the closing frontmatter delimiter.
	after := strings.TrimPrefix(strings.TrimPrefix(s, sep+"\n"), sep+"\r\n")
	end := strings.Index(after, "\n"+sep)
	if end < 0 {
		return nil, fmt.Errorf("soul: missing closing frontmatter delimiter")
	}

	front := after[:end]
	body := after[end+len("\n"+sep):]
	body = strings.TrimLeft(body, "\r\n")

	var sl Soul
	if err := yaml.Unmarshal([]byte(front), &sl); err != nil {
		return nil, fmt.Errorf("soul: parse frontmatter: %w", err)
	}
	sl.Persona = strings.TrimSpace(body)
	return &sl, nil
}

// Write serializes s to path, creating parent directories as needed.
func Write(path string, s *Soul) error {
	if s == nil {
		return errors.New("soul: cannot write nil")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("soul: mkdir: %w", err)
	}

	var buf bytes.Buffer
	buf.WriteString("---\n")
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(s); err != nil {
		return fmt.Errorf("soul: encode frontmatter: %w", err)
	}
	_ = enc.Close()
	buf.WriteString("---\n\n")
	if s.Persona != "" {
		buf.WriteString(strings.TrimSpace(s.Persona))
		buf.WriteByte('\n')
	}
	return os.WriteFile(path, buf.Bytes(), 0o600)
}

// SystemPrompt returns the text to inject as the LLM's system instruction.
// It combines the identity metadata (in a "facts about you" block) with the
// human-authored persona body.
func (s *Soul) SystemPrompt() string {
	if s == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString("# Who you are\n")
	if s.Company != "" {
		fmt.Fprintf(&b, "You are the security agent for **%s**.\n", s.Company)
	}
	if s.Industry != "" {
		fmt.Fprintf(&b, "Industry: %s.\n", s.Industry)
	}
	if s.DataSensitivity != "" {
		fmt.Fprintf(&b, "Data sensitivity: %s.\n", s.DataSensitivity)
	}
	if len(s.PrimaryStack) > 0 {
		fmt.Fprintf(&b, "Primary stack: %s.\n", strings.Join(s.PrimaryStack, ", "))
	}
	if len(s.Infra) > 0 {
		fmt.Fprintf(&b, "Infrastructure: %s.\n", strings.Join(s.Infra, ", "))
	}
	if s.SecretStorage != "" {
		fmt.Fprintf(&b, "Secret storage: %s — treat placeholders referencing this system as expected, not as leaks.\n", s.SecretStorage)
	}
	if len(s.Compliance) > 0 {
		fmt.Fprintf(&b, "Compliance frameworks: %s.\n", strings.Join(s.Compliance, ", "))
	}
	if s.RiskTolerance != "" {
		fmt.Fprintf(&b, "Risk tolerance: %s.\n", s.RiskTolerance)
	}
	if s.Escalation != "" {
		fmt.Fprintf(&b, "Escalation contact: %s.\n", s.Escalation)
	}
	if s.Persona != "" {
		b.WriteString("\n# Persona\n")
		b.WriteString(s.Persona)
	}
	return strings.TrimSpace(b.String())
}
