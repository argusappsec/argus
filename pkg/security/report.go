package security

import (
	"encoding/json"
	"fmt"
)

// Report is what every scanner Tool hands the model: the binary's own report,
// parsed into one finding shape so the model triages SAST, gitleaks and
// osv-scanner the same way, and so Argus can say things about a finding that
// the binary does not, such as that the code tried to suppress it.
//
// Field names follow the finding the model records with add_finding
// (pkg/report.Finding: rule_id, severity, file, line, title, description), so
// carrying a scanner hit into the report is a copy, not a translation.
type Report struct {
	// Scanner names the binary that produced the findings.
	Scanner  string    `json:"scanner"`
	Findings []Finding `json:"findings"`
	// Errors are the scanner's own per-file or per-rule errors (a file it
	// could not parse, a rule that timed out). They mean coverage is partial,
	// not that the scan failed.
	Errors []string `json:"errors,omitempty"`
}

// Finding is one scanner hit.
type Finding struct {
	// RuleID is the scanner's rule or advisory id: a SAST (opengrep or semgrep) check id, a
	// gitleaks rule, an OSV vulnerability id.
	RuleID string `json:"rule_id"`
	// Severity is as the scanner reports it; scanners do not share a scale.
	Severity string `json:"severity,omitempty"`
	// File is relative to the checkout under review when the scan ran inside
	// one, and as the scanner reported it otherwise.
	File        string `json:"file,omitempty"`
	Line        int    `json:"line,omitempty"`
	EndLine     int    `json:"end_line,omitempty"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	// SuppressedInRepo is set when the code under review marks this finding
	// as suppressed: an inline comment (`nosemgrep`, `noopengrep`, `gitleaks:allow`,
	// `#nosec`) or an entry in an ignore or config file the repository
	// carries. Argus never honours those (ADR 0027): the scanner ran with them
	// switched off, and the attempt is reported here as a signal, because a
	// pull request that silences a finding next to the code it changes
	// deserves attention. The organization's genuine false positives live in
	// its known-fps knowledge, which a pull request cannot write.
	SuppressedInRepo bool `json:"suppressed_in_repo,omitempty"`
	// Suppression says how the code tried to suppress it.
	Suppression string `json:"suppression,omitempty"`
	// Details carries what is specific to one scanner (a package and its fixed
	// versions, a rule's CWE).
	Details map[string]any `json:"details,omitempty"`
}

// suppressed marks f as suppressed in the repository, by how.
func (f *Finding) suppressed(how string) {
	f.SuppressedInRepo = true
	f.Suppression = how
}

// encode renders the report for the model. An empty scan encodes as an empty
// findings list, never as null, so "nothing found" reads unambiguously.
func (r Report) encode() (string, error) {
	if r.Findings == nil {
		r.Findings = []Finding{}
	}
	body, err := json.Marshal(r)
	if err != nil {
		return "", fmt.Errorf("%s: encode findings: %w", r.Scanner, err)
	}
	return string(body), nil
}
