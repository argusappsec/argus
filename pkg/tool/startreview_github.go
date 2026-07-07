package tool

import (
	"context"
	"errors"
	"fmt"

	"github.com/argusappsec/argus/pkg/codehost/github"
	"github.com/argusappsec/argus/pkg/session"
)

// Cloner is the subset of pkg/codehost/github we need: enough to ask "clone
// this repo at this ref into your cache, give me the resulting checkout".
// Declared as an interface here so tests can substitute a fake without
// touching the real codehost implementation.
type Cloner interface {
	Clone(ctx context.Context, u github.URL, ref string) (github.Checkout, error)
}

// NewStartReviewGitHub returns a `start_review_github` tool that clones a
// GitHub repository (via the supplied Cloner) and points the Session at the
// resulting checkout. After it succeeds, file-scoped tools work on the freshly
// cloned code.
func NewStartReviewGitHub(s *session.Session, c Cloner) Tool {
	return &startReviewGitHub{sess: s, cloner: c}
}

type startReviewGitHub struct {
	sess   *session.Session
	cloner Cloner
}

func (t *startReviewGitHub) Name() string { return "start_review_github" }

func (t *startReviewGitHub) Description() string {
	return "Start a security review on a GitHub repository. " +
		"Clones the repository (shallow) into a local cache and points subsequent " +
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
	rawURL, _ := args["url"].(string)
	if rawURL == "" {
		return "", errors.New("start_review_github: url is required")
	}
	u, err := github.ParseURL(rawURL)
	if err != nil {
		return "", fmt.Errorf("start_review_github: %w", err)
	}
	ref, _ := args["ref"].(string)

	co, err := t.cloner.Clone(ctx, u, ref)
	if err != nil {
		return "", fmt.Errorf("start_review_github: clone: %w", err)
	}

	t.sess.SetRoot(co.Path)
	return fmt.Sprintf("Cloned %s at %s to %s. Proceed with list_files / read_file / grep / run_semgrep / run_gitleaks / run_osv_scanner.", u.FullName, co.SHA, co.Path), nil
}
