package tool_test

import (
	"context"
	"regexp"
	"testing"

	"github.com/argusappsec/argus/pkg/session"
	"github.com/argusappsec/argus/pkg/tool"
)

// scannerToolName matches a scanner Tool name (run_sast, run_gitleaks, …).
var scannerToolName = regexp.MustCompile(`\brun_[a-z_]+`)

// TestStartReview_NamesNoScannerTheSessionMayLack: which scanners a Session
// has depends on the host and the kind of review (ADR 0027), and the start-review
// Tools cannot see the registry. So they point the agent at "the scanners this
// session has", never at a scanner by name that may not be registered — the
// agent already sees the real list among its tools.
func TestStartReview_NamesNoScannerTheSessionMayLack(t *testing.T) {
	local := tool.NewStartReviewLocal(session.New())
	localOut, err := local.Execute(context.Background(), map[string]any{"path": t.TempDir()})
	if err != nil {
		t.Fatalf("start_review_local: %v", err)
	}
	github := tool.NewStartReviewGitHub(session.New(), fakeCodeHost{root: t.TempDir()})
	githubOut, err := github.Execute(context.Background(), map[string]any{"url": "https://github.com/example/repo"})
	if err != nil {
		t.Fatalf("start_review_github: %v", err)
	}

	for what, text := range map[string]string{
		"start_review_local description":  local.Description(),
		"start_review_local result":       localOut,
		"start_review_github description": github.Description(),
		"start_review_github result":      githubOut,
	} {
		if names := scannerToolName.FindAllString(text, -1); len(names) > 0 {
			t.Errorf("%s names scanners %v the Session may not have: %q", what, names, text)
		}
	}
}
