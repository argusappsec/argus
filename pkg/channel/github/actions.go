package github

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/redcarbon-dev/argus/pkg/auth"
	"github.com/redcarbon-dev/argus/pkg/codehost"
	"github.com/redcarbon-dev/argus/pkg/report"
)

// canActOnReview reports whether role may change a PR's review from the thread
// (suppress a finding, re-scope the analysis). Viewers are explain-only (ADR
// 0008 / slice 6): they keep the conversational read access from the prior
// slice but cannot mutate the review. The gate lives at the tool layer so a
// refusal is uniform regardless of how the agent is prompted.
func canActOnReview(role auth.Role) bool {
	return role == auth.RoleAdmin || role == auth.RoleAnalyst
}

// errViewerWriteDenied is the tool-layer refusal a viewer's write attempt gets.
// It is returned as a tool error so the agent relays it in the thread rather
// than silently performing — or silently dropping — the action.
var errViewerWriteDenied = errors.New(
	"permission denied: your role is explain-only on this channel; suppressing findings and re-scoping the review require the analyst or admin role")

// suppressFinding is the `suppress_finding` PR comment-action tool. An analyst
// or admin accepting a false positive in the thread removes the finding from
// this PR's review immediately (hard, local to the PR) and the channel re-posts
// the trimmed review. The acceptance is also written to MEMORY as advisory
// context the agent re-judges per situation in future reviews — never a global
// mute (ADR 0008 / slice 6). RBAC is enforced here at the tool layer.
type suppressFinding struct {
	role   auth.Role
	store  *prReviewStore
	host   codehost.CodeHost
	repo   codehost.Repo
	number int
	// recordAdvisory persists the soft, advisory MEMORY note. It is wired to the
	// daemon's serialized MEMORY writer so the note cannot be lost to a
	// concurrent curator rewrite.
	recordAdvisory func(line string) error
}

func (t *suppressFinding) Name() string { return "suppress_finding" }

func (t *suppressFinding) Description() string {
	return "Accept a finding as a false positive for THIS pull request. The finding is removed from " +
		"the review immediately and the review is re-posted without it; the acceptance is also recorded " +
		"in MEMORY as advisory context (re-judged per situation in future reviews — NOT a global mute). " +
		"Identify the finding by its rule_id (and file when more than one finding shares the rule). " +
		"Only call this when a teammate has asked you to ignore a finding as a false positive."
}

func (t *suppressFinding) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"rule_id": map[string]any{"type": "string", "description": "The rule_id of the finding to suppress."},
			"file":    map[string]any{"type": "string", "description": "Optional file path, to disambiguate when several findings share the rule_id."},
			"reason":  map[string]any{"type": "string", "description": "Short note on why this is a false positive (recorded in MEMORY)."},
		},
		"required": []string{"rule_id"},
	}
}

func (t *suppressFinding) Execute(ctx context.Context, args map[string]any) (string, error) {
	if !canActOnReview(t.role) {
		return "", errViewerWriteDenied
	}
	ruleID, _ := args["rule_id"].(string)
	if strings.TrimSpace(ruleID) == "" {
		return "", errors.New("suppress_finding: rule_id required")
	}
	file, _ := args["file"].(string)
	reason, _ := args["reason"].(string)

	state, err := t.store.Load(t.repo.FullName, t.number)
	if err != nil {
		return "", err
	}

	match := matchFinding(state, ruleID, file)
	if match == nil {
		return fmt.Sprintf("No finding with rule_id %q%s is on this PR's review; nothing to suppress.",
			ruleID, fileQualifier(file)), nil
	}
	if !state.Suppress(match.ID) {
		return fmt.Sprintf("Finding %q at %s was already suppressed on this PR.", ruleID, location(*match)), nil
	}

	// Persist the suppression BEFORE re-posting: if the GitHub write then fails,
	// the suppression is already durable, so the next review (e.g. a synchronize)
	// still drops the finding and self-heals. The reverse order would risk a
	// finding the teammate accepted reappearing on the next push.
	if err := t.store.Save(t.repo.FullName, t.number, state); err != nil {
		return "", err
	}

	// Re-post the review without the suppressed finding (replace the prior one).
	diff, err := t.host.FetchPRDiff(ctx, t.repo, t.number)
	if err != nil {
		return "", fmt.Errorf("suppress_finding: fetch diff: %w", err)
	}
	review := renderReview(state.HeadSHA, state.Summary, state.LiveFindings(), diff)
	if err := t.host.PostReview(ctx, t.repo, t.number, review, true); err != nil {
		return "", fmt.Errorf("suppress_finding: re-post review: %w", err)
	}
	if err := t.recordAdvisory(memoryAdvisory(t.repo.FullName, t.number, *match, reason)); err != nil {
		return "", fmt.Errorf("suppress_finding: record advisory: %w", err)
	}

	return fmt.Sprintf("Suppressed finding %q at %s on this PR and re-posted the review without it. "+
		"Recorded as advisory in MEMORY (re-judged per context in future reviews, not a global mute).",
		ruleID, location(*match)), nil
}

// matchFinding finds the finding on the review to suppress: by rule_id, narrowed
// by file when supplied. Returns nil when nothing matches.
func matchFinding(state *prReview, ruleID, file string) *report.Finding {
	for i := range state.Findings {
		f := &state.Findings[i]
		if f.RuleID != ruleID {
			continue
		}
		if file != "" && f.File != file {
			continue
		}
		return f
	}
	return nil
}

func fileQualifier(file string) string {
	if file == "" {
		return ""
	}
	return " at " + file
}

// memoryAdvisory renders the soft, advisory MEMORY note for an accepted false
// positive. It is explicitly guidance, not a content-keyed global mute: future
// reviews re-judge the same pattern per context (ADR 0008 / slice 6). The
// caller persists it through the daemon's serialized MEMORY writer.
func memoryAdvisory(repo string, number int, f report.Finding, reason string) string {
	line := fmt.Sprintf(
		"- Advisory (false positive accepted on %s#%d): finding `%s`%s was judged a false positive. "+
			"Treat as guidance only — re-judge the same pattern per context in future reviews; this is NOT a global mute.",
		repo, number, f.RuleID, fileQualifier(f.File))
	if reason = strings.TrimSpace(reason); reason != "" {
		line += " Reason: " + reason
	}
	return line
}

// rescopeReview is the `rescope_review` PR comment-action tool. An analyst or
// admin asking Argus to "also check the auth module" gets a focused additional
// pass, not a full re-review: the tool clones the PR head, points the
// file-scoped tools at the checkout, and hands the agent the area to inspect so
// it scans there with grep/read_file/run_semgrep within the SAME thread turn.
type rescopeReview struct {
	role    auth.Role
	store   *prReviewStore
	host    codehost.CodeHost
	repo    codehost.Repo
	number  int
	setRoot func(path string)
}

func (t *rescopeReview) Name() string { return "rescope_review" }

func (t *rescopeReview) Description() string {
	return "Run a focused additional security pass over a specific area of this pull request (e.g. a " +
		"module or directory the teammate asked you to also check). This checks out the PR head and lets " +
		"you inspect that area with read_file / grep / run_semgrep — it does NOT re-run the whole review. " +
		"Report what you find in your reply. Only call this when a teammate asks you to also check or " +
		"re-examine a part of the change."
}

func (t *rescopeReview) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"area": map[string]any{"type": "string", "description": "The area to focus on (a path, module, or feature named by the teammate)."},
		},
		"required": []string{"area"},
	}
}

func (t *rescopeReview) Execute(ctx context.Context, args map[string]any) (string, error) {
	if !canActOnReview(t.role) {
		return "", errViewerWriteDenied
	}
	area, _ := args["area"].(string)
	if strings.TrimSpace(area) == "" {
		return "", errors.New("rescope_review: area required")
	}

	state, err := t.store.Load(t.repo.FullName, t.number)
	if err != nil {
		return "", err
	}
	if state.HeadSHA == "" {
		return "No review has run on this PR yet, so there is no head commit to re-scope against. " +
			"A re-scope follows an initial review.", nil
	}

	co, err := t.host.Clone(ctx, t.repo, state.HeadSHA)
	if err != nil {
		return "", fmt.Errorf("rescope_review: clone PR head: %w", err)
	}
	t.setRoot(co.Path)

	return fmt.Sprintf(
		"Checked out the PR head (%s). Focus your additional analysis on: %s. "+
			"Use list_files / grep / read_file / run_semgrep scoped to that area, then summarize anything "+
			"relevant in your reply. Do not re-review the rest of the change.",
		co.SHA, area), nil
}
