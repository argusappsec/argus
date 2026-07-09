package tool

import (
	"context"
	"errors"
	"fmt"

	"github.com/argusappsec/argus/pkg/codehost"
	"github.com/argusappsec/argus/pkg/session"
)

// RepoCloner is the subset of codehost.CodeHost the tool needs: parse a repo
// reference and clone it (authenticated, via an installation token) into the
// local cache. Declared as an interface here so tests can substitute a fake
// without standing up the real GitHub client. codehost.CodeHost satisfies it.
type RepoCloner interface {
	ParseURL(raw string) (codehost.Repo, error)
	Clone(ctx context.Context, repo codehost.Repo, ref string) (codehost.Checkout, error)
}

// NewStartReviewGitHub returns a `start_review_github` tool that clones a
// GitHub repository through the shared authenticated CodeHost and points the
// Session at the resulting checkout. Because the clone rides an installation
// token, a private repo the App is installed on succeeds — the same reach the
// webhook path has. After it succeeds, file-scoped tools work on the checkout.
//
// host is nil on a GitHub-free install (no codehosts: configured); the tool
// then fails with a clear, user-facing error naming what to enable rather than
// silently doing nothing.
func NewStartReviewGitHub(s *session.Session, host RepoCloner) Tool {
	return &startReviewGitHub{sess: s, host: host}
}

type startReviewGitHub struct {
	sess *session.Session
	host RepoCloner
}

func (t *startReviewGitHub) Name() string { return "start_review_github" }

func (t *startReviewGitHub) Description() string {
	return "Start a security review on a GitHub repository. " +
		"Clones the repository (shallow, authenticated so private repos the App can access work) into a local cache and points subsequent " +
		"file-scoped tools (list_files, read_file, grep, run_semgrep, run_gitleaks, run_osv_scanner) at the checkout. " +
		"Use when the user provides a github.com URL or short form like github.com/owner/repo. " +
		"For paths already on disk use start_review_local instead."
}

func (t *startReviewGitHub) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"url": map[string]any{
				"type":        "string",
				"description": "GitHub repo URL (https://github.com/owner/repo) or short form (github.com/owner/repo).",
			},
			"ref": map[string]any{
				"type":        "string",
				"description": "Optional branch, tag, or commit SHA. Default: remote HEAD.",
			},
		},
		"required": []string{"url"},
	}
}

func (t *startReviewGitHub) Execute(ctx context.Context, args map[string]any) (string, error) {
	if t.host == nil {
		return "", errors.New("start_review_github: no codehost is configured — add a github entry under `codehosts:` in argus.yaml to review GitHub repositories")
	}
	rawURL, _ := args["url"].(string)
	if rawURL == "" {
		return "", errors.New("start_review_github: url is required")
	}
	repo, err := t.host.ParseURL(rawURL)
	if err != nil {
		return "", fmt.Errorf("start_review_github: %w", err)
	}
	ref, _ := args["ref"].(string)

	co, err := t.host.Clone(ctx, repo, ref)
	if err != nil {
		return "", fmt.Errorf("start_review_github: clone: %w", err)
	}

	t.sess.SetRoot(co.Path)
	return fmt.Sprintf("Cloned %s at %s to %s. Proceed with list_files / read_file / grep / run_semgrep / run_gitleaks / run_osv_scanner.", repo.FullName, co.SHA, co.Path), nil
}
