// Package report assembles and persists security review reports.
//
// A Report is markdown-with-frontmatter: human-readable on its own, but with
// structured findings in YAML so that downstream tools (renderers, diffs)
// don't need to re-parse the prose.
//
// Finding IDs are content-derived (rule_id + normalized snippet) so they
// survive refactors that move code across files or lines.
package report

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Severity buckets used by findings. Free-form strings would let LLMs invent
// new ones, so we keep them as named constants.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"
)

// Finding is one security observation.
type Finding struct {
	ID          string `yaml:"id"          json:"id"`
	Severity    string `yaml:"severity"    json:"severity"`
	RuleID      string `yaml:"rule_id"     json:"rule_id"`
	File        string `yaml:"file"        json:"file"`
	Line        int    `yaml:"line"        json:"line"`
	Snippet     string `yaml:"snippet"     json:"snippet"`
	Title       string `yaml:"title"       json:"title"`
	Description string `yaml:"description" json:"description"`
	Remediation string `yaml:"remediation" json:"remediation"`
}

// Report is the aggregate produced for a single (repo, sha).
type Report struct {
	Target    string    `yaml:"target"`
	SHA       string    `yaml:"sha"`
	Timestamp time.Time `yaml:"timestamp"`
	Summary   string    `yaml:"summary"`
	Findings  []Finding `yaml:"findings"`
}

// Writer persists reports under a root directory, one file per (repo, sha).
type Writer struct {
	root string
}

// NewWriter creates a Writer rooted at dir. The dir is created lazily on the
// first write.
func NewWriter(dir string) *Writer {
	return &Writer{root: dir}
}

// Write serializes rep to disk and returns the path of the written file.
func (w *Writer) Write(rep Report) (string, error) {
	slug := Slugify(rep.Target)
	dir := filepath.Join(w.root, slug)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("mkdir report dir: %w", err)
	}
	path := filepath.Join(dir, rep.SHA+".md")
	content := render(rep)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return "", fmt.Errorf("write report: %w", err)
	}
	return path, nil
}

// PathFor returns the path Write would produce for a report on target@sha,
// without writing anything. Callers that need to reference the report file
// after an agent run (which writes via finalize_report internally) use this
// instead of re-deriving the layout.
func (w *Writer) PathFor(target, sha string) string {
	return filepath.Join(w.root, Slugify(target), sha+".md")
}

// ComputeFindingID returns a content-stable ID for a finding. The ID survives
// whitespace changes and line movements; it changes only when rule_id or the
// substantive snippet content changes.
func ComputeFindingID(ruleID, snippet string) string {
	norm := normalizeSnippet(snippet)
	sum := sha256.Sum256([]byte(ruleID + "\x00" + norm))
	return hex.EncodeToString(sum[:])[:12]
}

func normalizeSnippet(s string) string {
	// Lowercase + collapse all whitespace runs to a single space.
	var b strings.Builder
	b.Grow(len(s))
	prevSpace := true
	for _, r := range strings.ToLower(s) {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			if !prevSpace {
				b.WriteByte(' ')
				prevSpace = true
			}
			continue
		}
		b.WriteRune(r)
		prevSpace = false
	}
	return strings.TrimSpace(b.String())
}

// Slugify turns a target/repo name into a single safe path segment by replacing
// path separators (and spaces). Exported so other on-disk stores keyed by the
// same repo name (e.g. the GitHub channel's per-PR review state) produce
// identical, collision-free slugs instead of maintaining a second copy.
func Slugify(s string) string {
	// Replace path separators so the result is a single directory name.
	r := strings.NewReplacer("/", "_", "\\", "_", ":", "_", " ", "_")
	return r.Replace(s)
}

// render emits markdown with a minimal hand-rolled YAML frontmatter so we
// avoid pulling a YAML dependency for the trivial shapes we produce.
func render(rep Report) string {
	var b strings.Builder
	b.WriteString("---\n")
	fmt.Fprintf(&b, "target: %s\n", yamlString(rep.Target))
	fmt.Fprintf(&b, "sha: %s\n", yamlString(rep.SHA))
	fmt.Fprintf(&b, "timestamp: %s\n", rep.Timestamp.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "summary: %s\n", yamlString(rep.Summary))
	b.WriteString("findings:\n")
	for _, f := range rep.Findings {
		b.WriteString("  - id: " + yamlString(f.ID) + "\n")
		b.WriteString("    severity: " + yamlString(f.Severity) + "\n")
		b.WriteString("    rule_id: " + yamlString(f.RuleID) + "\n")
		b.WriteString("    file: " + yamlString(f.File) + "\n")
		fmt.Fprintf(&b, "    line: %d\n", f.Line)
		b.WriteString("    snippet: " + yamlString(f.Snippet) + "\n")
		b.WriteString("    title: " + yamlString(f.Title) + "\n")
		b.WriteString("    description: " + yamlString(f.Description) + "\n")
		b.WriteString("    remediation: " + yamlString(f.Remediation) + "\n")
	}
	b.WriteString("---\n\n")
	fmt.Fprintf(&b, "# Security review — %s\n\n", rep.Target)
	fmt.Fprintf(&b, "Commit `%s`. %s\n\n", rep.SHA, rep.Summary)
	for _, f := range rep.Findings {
		fmt.Fprintf(&b, "## [%s] %s\n\n", strings.ToUpper(f.Severity), f.Title)
		fmt.Fprintf(&b, "- **Rule**: `%s`\n", f.RuleID)
		fmt.Fprintf(&b, "- **Location**: `%s:%d`\n\n", f.File, f.Line)
		if f.Snippet != "" {
			b.WriteString("```\n" + f.Snippet + "\n```\n\n")
		}
		if f.Description != "" {
			b.WriteString(f.Description + "\n\n")
		}
		if f.Remediation != "" {
			b.WriteString("**Remediation**: " + f.Remediation + "\n\n")
		}
	}
	return b.String()
}

// yamlString quotes any value that could be ambiguous in YAML.
func yamlString(s string) string {
	if s == "" {
		return `""`
	}
	if strings.ContainsAny(s, ":#\"'\n\r\t") || strings.HasPrefix(s, " ") || strings.HasSuffix(s, " ") {
		// Use a double-quoted scalar with minimal escaping.
		esc := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\r", `\r`, "\t", `\t`).Replace(s)
		return `"` + esc + `"`
	}
	return s
}
