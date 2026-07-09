package tool

import (
	"context"
	"errors"
	"fmt"

	"github.com/argusappsec/argus/pkg/soul"
)

// NewWriteSoul returns a `write_soul` tool that persists the agent's identity
// to soulPath. Used by the `argus init` bootstrap interview: the interviewer
// agent asks the user questions, then calls this tool with the collected
// answers in structured form. The agent reads the schema from Schema() and
// builds the args itself.
func NewWriteSoul(soulPath string) Tool { return &writeSoul{path: soulPath} }

type writeSoul struct{ path string }

func (w *writeSoul) Name() string { return "write_soul" }

func (w *writeSoul) Description() string {
	return "Persist the agent's identity (SOUL.md) for the current user. " +
		"Call exactly once at the end of the bootstrap interview, after collecting " +
		"company, industry, the data sensitivity of what they handle, their primary " +
		"tech stack, their infrastructure, how they store secrets, compliance " +
		"frameworks, risk tolerance, severity rules, output language, and a persona body."
}

func (w *writeSoul) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"company": map[string]any{
				"type":        "string",
				"description": "Company / organization the agent serves.",
			},
			"industry": map[string]any{
				"type":        "string",
				"description": "Industry vertical (e.g. saas, fintech, healthcare, cybersecurity).",
			},
			"data_sensitivity": map[string]any{
				"type":        "string",
				"enum":        []string{"public", "internal", "pii", "phi", "pci", "regulated"},
				"description": "Sensitivity of the data the software handles. Drives severity calibration of crypto/leak findings.",
			},
			"primary_stack": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "string"},
				"description": "Languages / runtimes the codebase predominantly uses (e.g. [\"Go\", \"Python\", \"TypeScript\"]).",
			},
			"infra": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "string"},
				"description": "Platforms / orchestrators / key data stores (e.g. [\"AWS\", \"Kubernetes\", \"PostgreSQL\"]).",
			},
			"secret_storage": map[string]any{
				"type":        "string",
				"description": "Where production secrets actually live (e.g. \"HashiCorp Vault\", \"AWS Secrets Manager\", \"K8s Secrets\"). Used to suppress false positives on placeholder references.",
			},
			"compliance": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "string"},
				"description": "Compliance frameworks that apply (e.g. SOC2, ISO27001, HIPAA, PCI-DSS, GDPR).",
			},
			"risk_tolerance": map[string]any{
				"type":        "string",
				"enum":        []string{"low", "medium", "high"},
				"description": "How aggressively to surface findings.",
			},
			"language": map[string]any{
				"type":        "string",
				"description": "Language the agent writes findings, reports and replies in (e.g. \"italian\", \"english\"). Omit to mirror whatever language the agent is addressed in.",
			},
			"severity_rules": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "string"},
				"description": "Non-negotiable severity policies, one rule per entry (e.g. \"Any leak of customer PII is High regardless of CVSS\"). Only rules the user actually stated.",
			},
			"persona": map[string]any{
				"type":        "string",
				"description": "Markdown identity body in two sections: \"## Mission\" — who the agent serves, what it does and does not do — and \"## Conduct\" — tone, audience, priorities, plus any context that doesn't fit a structured field.",
			},
		},
		"required": []string{"company", "persona"},
	}
}

func (w *writeSoul) Execute(_ context.Context, args map[string]any) (string, error) {
	company, _ := args["company"].(string)
	persona, _ := args["persona"].(string)
	if company == "" {
		return "", errors.New("write_soul: company is required")
	}
	if persona == "" {
		return "", errors.New("write_soul: persona is required")
	}

	s := &soul.Soul{
		Company:         company,
		Industry:        stringOpt(args, "industry"),
		DataSensitivity: stringOpt(args, "data_sensitivity"),
		PrimaryStack:    stringSliceOpt(args, "primary_stack"),
		Infra:           stringSliceOpt(args, "infra"),
		SecretStorage:   stringOpt(args, "secret_storage"),
		Compliance:      stringSliceOpt(args, "compliance"),
		RiskTolerance:   stringOpt(args, "risk_tolerance"),
		Language:        stringOpt(args, "language"),
		SeverityRules:   stringSliceOpt(args, "severity_rules"),
		Persona:         persona,
	}

	if err := soul.Write(w.path, s); err != nil {
		return "", fmt.Errorf("write_soul: %w", err)
	}
	return fmt.Sprintf("SOUL.md written to %s.", w.path), nil
}

func stringOpt(args map[string]any, key string) string {
	v, _ := args[key].(string)
	return v
}

// stringSliceOpt extracts a string slice from args, accepting both []string
// (from native callers) and []any (the typical shape from JSON-decoded LLM
// arguments where each item is a string).
func stringSliceOpt(args map[string]any, key string) []string {
	raw, ok := args[key]
	if !ok || raw == nil {
		return nil
	}
	switch v := raw.(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, x := range v {
			if s, ok := x.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
