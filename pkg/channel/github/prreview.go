package github

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	"github.com/redcarbon-dev/argus/pkg/report"
)

// prReview is the channel-owned record of the review argus[bot] last posted on
// a pull request, keyed by repo + PR number (NOT the head SHA — a comment event
// does not carry one, and the record must be findable from a comment turn). It
// holds what the channel needs to re-render and re-post the review when a
// teammate suppresses a finding from the thread, and the set of findings
// hard-suppressed for THIS PR.
//
// Suppression is deliberately local and hard here (ADR 0008 / slice 6): the IDs
// in Suppressed are filtered out of every posting of this PR's review,
// including the re-review a later `synchronize` triggers, so an accepted false
// positive stays gone for the life of the PR. The cross-PR carryover is the
// separate, SOFT MEMORY advisory the agent re-judges per situation — never a
// global mute keyed by these IDs.
type prReview struct {
	HeadSHA    string           `json:"head_sha"`
	Summary    string           `json:"summary"`
	Findings   []report.Finding `json:"findings"`
	Suppressed []string         `json:"suppressed,omitempty"`
}

// IsSuppressed reports whether finding id has been hard-suppressed on this PR.
func (r *prReview) IsSuppressed(id string) bool {
	return slices.Contains(r.Suppressed, id)
}

// Suppress records finding id as hard-suppressed for this PR. It returns false
// when the id was already suppressed (idempotent), true on first suppression.
func (r *prReview) Suppress(id string) bool {
	if r.IsSuppressed(id) {
		return false
	}
	r.Suppressed = append(r.Suppressed, id)
	return true
}

// LiveFindings returns the review's findings minus the ones suppressed for this
// PR — the set that is actually posted to GitHub.
func (r *prReview) LiveFindings() []report.Finding {
	out := make([]report.Finding, 0, len(r.Findings))
	for _, f := range r.Findings {
		if r.IsSuppressed(f.ID) {
			continue
		}
		out = append(out, f)
	}
	return out
}

// prReviewStore persists prReview records under a directory on the daemon host.
type prReviewStore struct{ dir string }

// newPRReviewStore returns a store rooted at <home>/github/reviews.
func newPRReviewStore(home string) *prReviewStore {
	return &prReviewStore{dir: filepath.Join(home, "github", "reviews")}
}

// Load returns the stored review for (repo, number). A missing record is not an
// error: it yields a zero-value prReview, the correct state before the first
// review is posted.
func (s *prReviewStore) Load(repo string, number int) (*prReview, error) {
	b, err := os.ReadFile(s.path(repo, number))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return &prReview{}, nil
		}
		return nil, fmt.Errorf("github: read pr review state: %w", err)
	}
	var r prReview
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("github: parse pr review state: %w", err)
	}
	return &r, nil
}

// Save writes the review record for (repo, number) atomically.
func (s *prReviewStore) Save(repo string, number int, r *prReview) error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return fmt.Errorf("github: pr review state dir: %w", err)
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("github: marshal pr review state: %w", err)
	}
	path := s.path(repo, number)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("github: write pr review state: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("github: commit pr review state: %w", err)
	}
	return nil
}

// path is the on-disk location for one PR's review record.
func (s *prReviewStore) path(repo string, number int) string {
	return filepath.Join(s.dir, fmt.Sprintf("%s#%d.json", report.Slugify(repo), number))
}
