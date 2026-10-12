package github

import (
	"context"
	"regexp"
	"testing"

	"github.com/argusappsec/argus/pkg/auth"
	"github.com/argusappsec/argus/pkg/codehost"
)

// TestRescope_NamesNoScannerTheSessionMayLack: which scanners a Session has
// depends on the host and on the kind of review (ADR 0027), and the re-scope
// Tool cannot see the registry. It points the agent at the scanners among its
// tools instead of naming one, such as a SAST engine, that may be absent.
func TestRescope_NamesNoScannerTheSessionMayLack(t *testing.T) {
	store := newPRReviewStore(t.TempDir())
	repo := codehost.Repo{Owner: "o", Name: "r", FullName: "o/r"}
	if err := store.Save(repo.FullName, 42, &prReview{HeadSHA: "headsha111"}); err != nil {
		t.Fatal(err)
	}
	rescope := &rescopeReview{
		role:    auth.RoleAnalyst,
		store:   store,
		host:    &fakeHost{clonePath: t.TempDir(), cloneSHA: "headsha111"},
		repo:    repo,
		number:  42,
		setRoot: func(string) {},
	}

	out, err := rescope.Execute(context.Background(), map[string]any{"area": "pkg/auth"})
	if err != nil {
		t.Fatalf("rescope_review: %v", err)
	}

	scanner := regexp.MustCompile(`\brun_[a-z_]+`)
	for what, text := range map[string]string{"description": rescope.Description(), "result": out} {
		if names := scanner.FindAllString(text, -1); len(names) > 0 {
			t.Errorf("rescope_review %s names scanners %v the Session may not have: %q", what, names, text)
		}
	}
}
