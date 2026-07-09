// Package codehost defines the minimal interface the channel and agent use to
// talk to a code-hosting platform (ADR 0010). GitHub is the only
// implementation today (pkg/codehost/github); the interface marks the intent
// and keeps host-specific types from leaking across the codebase. It is
// expected to be reshaped when a second host (GitLab, …) lands.
package codehost

import "context"

// Repo identifies a repository on a code host.
type Repo struct {
	Host     string
	Owner    string
	Name     string
	FullName string // canonical "github.com/<owner>/<name>"
}

// Checkout is a local working copy pinned at a resolved commit.
type Checkout struct {
	Path string // absolute path on disk
	SHA  string // resolved commit SHA
}

// PRDiff is the set of files a pull request changed, with the patch hunks that
// locate the change on the head side. It is what makes a review diff-aware
// (ADR 0009): the scanners run over the whole tree, but the agent learns which
// lines the PR actually touched from here, and the channel uses it to decide
// inline-comment vs. summary placement.
type PRDiff struct {
	Files []ChangedFile
}

// ChangedFile is one file in a PRDiff.
type ChangedFile struct {
	Path   string // path on the head side
	Status string // "added", "modified", "removed", "renamed", …
	Patch  string // the raw unified-diff patch hunk text (may be empty, e.g. binary)
	Hunks  []Hunk // parsed hunks, locating the change on the head side
}

// Hunk locates a contiguous run of changed/context lines on the head (new)
// side of the diff. GitHub inline comments may attach to any line within a
// hunk on the RIGHT side.
type Hunk struct {
	NewStart int // first line number on the head side
	NewLines int // number of lines on the head side
}

// IsChangedLine reports whether (path, line) falls within the PR's diff — i.e.
// whether a finding there can be posted as an inline review comment. A finding
// off the diff is causal/off-diff and belongs in the summary body instead.
func (d PRDiff) IsChangedLine(path string, line int) bool {
	if path == "" || line <= 0 {
		return false
	}
	for _, f := range d.Files {
		if f.Path != path {
			continue
		}
		for _, h := range f.Hunks {
			if line >= h.NewStart && line < h.NewStart+h.NewLines {
				return true
			}
		}
	}
	return false
}

// Review is what argus[bot] posts on a pull request: a summary body plus inline
// comments on changed lines. Causal off-diff findings live in the summary
// because GitHub inline comments can only attach to the diff (ADR 0009).
type Review struct {
	HeadSHA string          // commit the inline comments attach to (RIGHT side)
	Summary string          // summary body (rendered markdown)
	Inline  []InlineComment // one per finding on a changed line
}

// InlineComment is a single inline review comment on a changed line.
type InlineComment struct {
	Path string
	Line int
	Body string
}

// CodeHost is the surface the GitHub channel needs. It is deliberately small:
// the operations already in hand, not a speculative model of "any forge".
type CodeHost interface {
	// ParseURL parses a repo (or PR) URL into a Repo.
	ParseURL(raw string) (Repo, error)

	// Clone produces a local checkout of repo at ref, authenticated so that
	// private repositories the installation can access succeed. An empty ref
	// means the default branch.
	Clone(ctx context.Context, repo Repo, ref string) (Checkout, error)

	// PostComment posts a comment on the given pull request (issue comment on
	// the PR), as the App's bot identity.
	PostComment(ctx context.Context, repo Repo, number int, body string) error

	// FetchPRDiff returns the files a pull request changed and their patch
	// hunks (GitHub: pulls/{n}/files). It backs the pr_diff tool and the
	// inline-vs-summary placement decision (ADR 0009).
	FetchPRDiff(ctx context.Context, repo Repo, number int) (PRDiff, error)

	// PostReview posts argus[bot]'s review: inline comments on changed lines
	// plus a summary body. When replace is true (a synchronize event), the
	// bot's prior review artifacts are removed first so a new push updates the
	// review in place rather than stacking a duplicate.
	PostReview(ctx context.Context, repo Repo, number int, review Review, replace bool) error

	// InstallationRepos lists the canonical names of the repositories the
	// installation that owns repo can access. The installation is derived from
	// repo (ADR 0015), so gating consults the repos of the event's
	// installation, never a pinned one. It backs repo gating (ADR 0008).
	InstallationRepos(ctx context.Context, repo Repo) ([]string, error)
}
