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

	// InstallationRepos lists the canonical names of the repositories the
	// installation can access. It backs repo gating (ADR 0008).
	InstallationRepos(ctx context.Context) ([]string, error)
}
