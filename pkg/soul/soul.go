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

	// Language is the language the agent writes in — findings, reports and
	// chat replies (e.g. "italian", "english"). Empty means the agent mirrors
	// whatever language it is addressed in.
	Language string `yaml:"language,omitempty"`

	// SeverityRules are non-negotiable severity policies set by the
	// organization, e.g. "Any leak of customer PII is High regardless of
	// CVSS". Rendered as explicit rules the model must apply over its own
	// judgement.
	SeverityRules []string `yaml:"severity_rules,omitempty"`

	// Persona is the markdown body after the frontmatter. Free-form prose
	// the human (or the bootstrap agent) wrote, ideally structured in two
	// sections: "## Mission" (who the agent serves, what it does and does
	// not do) and "## Conduct" (tone, audience, priorities).
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
// riskToleranceGuidance turns the bare risk-tolerance label into an explicit
// severity-reporting instruction. Without this the model reads "high" as "they
// accept risk → only flag criticals" and silently under-reports.
func riskToleranceGuidance(level string) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "low":
		return "Risk tolerance is LOW: be thorough — report findings down to Low severity and do not silently drop minor issues."
	case "medium":
		return "Risk tolerance is MEDIUM: report Medium severity and above; surface Low only when it sits on a sensitive path or a trust boundary."
	case "high":
		return "Risk tolerance is HIGH: prioritize High and Critical findings; lower-severity issues may be noted briefly or deferred — but never drop an issue that touches sensitive data or an authorization boundary."
	default:
		return fmt.Sprintf("Risk tolerance: %s — calibrate the severity threshold you report at accordingly.", level)
	}
}

// dataSensitivityGuidance turns the data-sensitivity label into a severity
// instruction, so e.g. "pii" raises the floor on data-exposure findings rather
// than sitting in the prompt as an inert token.
func dataSensitivityGuidance(kind string) string {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "public":
		return "Data sensitivity: public — stored-data exposure is low impact; weight integrity, availability and authorization instead."
	case "internal":
		return "Data sensitivity: internal — calibrate exposure severity to business impact."
	case "pii":
		return "Data sensitivity: PII — treat any exposure of personal data as at least High severity regardless of CVSS, and weigh data-protection obligations."
	case "phi":
		return "Data sensitivity: PHI — treat exposure of health data as Critical; health-privacy obligations apply."
	case "pci":
		return "Data sensitivity: cardholder data — treat exposure of payment data as Critical; PCI-DSS scope applies."
	case "regulated":
		return "Data sensitivity: regulated — treat exposure of regulated data as at least High and weigh the governing obligations."
	default:
		return fmt.Sprintf("Data sensitivity: %s — raise the severity of data-exposure findings accordingly.", kind)
	}
}

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
	if len(s.PrimaryStack) > 0 {
		fmt.Fprintf(&b, "Primary stack: %s.\n", strings.Join(s.PrimaryStack, ", "))
	}
	if len(s.Infra) > 0 {
		fmt.Fprintf(&b, "Infrastructure: %s.\n", strings.Join(s.Infra, ", "))
	}

	// Every line below attaches MEANING, not a bare label: the model is told
	// what the value implies for the review, otherwise it interprets a token
	// like "risk tolerance: high" however it likes (and tends to under-report).
	if s.DataSensitivity != "" {
		fmt.Fprintf(&b, "%s\n", dataSensitivityGuidance(s.DataSensitivity))
	}
	if s.SecretStorage != "" {
		fmt.Fprintf(&b, "Secret storage: %s — treat placeholders referencing this system as expected, not as leaks.\n", s.SecretStorage)
	}
	if len(s.Compliance) > 0 {
		fmt.Fprintf(&b, "Compliance frameworks: %s — factor these obligations into severity and remediation.\n", strings.Join(s.Compliance, ", "))
	}
	if s.RiskTolerance != "" {
		fmt.Fprintf(&b, "%s\n", riskToleranceGuidance(s.RiskTolerance))
	}
	if s.Language != "" {
		fmt.Fprintf(&b, "Write every finding, report and reply in %s, keeping code identifiers and technical terms in their original form.\n", s.Language)
	}
	if len(s.SeverityRules) > 0 {
		b.WriteString("\n# Severity rules\n")
		b.WriteString("Non-negotiable policies set by the organization. When one applies, it overrides your own severity judgement:\n")
		for _, r := range s.SeverityRules {
			fmt.Fprintf(&b, "- %s\n", r)
		}
	}
	if s.Persona != "" {
		b.WriteString("\n# Persona\n")
		b.WriteString(s.Persona)
	}
	return strings.TrimSpace(b.String())
}
