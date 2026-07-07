package github

import (
	"context"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/argusappsec/argus/pkg/provider"
)

// routerProvider answers each model turn from the SHAPE of the request rather
// than a fixed script, so it stays deterministic under the async memory curator
// that shares the channel's single provider. It routes on the last message:
// a review seed → add_finding then finalize_report; a "false positive" comment →
// suppress_finding then a text reply; an "also check" comment → rescope_review
// then a text reply; anything else → a plain text reply. Curator turns (their
// transcript seed / persona) terminate immediately so MEMORY is left intact.
type routerProvider struct{ mu sync.Mutex }

func (p *routerProvider) Generate(_ context.Context, req provider.Request) (provider.Response, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	usage := provider.Usage{InputTokens: 10, OutputTokens: 5}

	last := req.Messages[len(req.Messages)-1]

	// Memory curator: end the turn with no tool calls and no memory write.
	if strings.Contains(req.System, "memory curator") ||
		strings.Contains(last.Content, "transcript of the session to curate") {
		return provider.Response{Text: "nothing to curate", Usage: usage}, nil
	}

	// After a tool result, decide whether to terminate or continue the review.
	if last.Role == "tool" {
		if toolResult(last, "add_finding") {
			return call("f1", "finalize_report", map[string]any{"summary": "One high-severity issue found."}, usage), nil
		}
		// suppress_finding / rescope_review (or their RBAC refusal): wrap up in prose.
		return provider.Response{Text: "Done — see my note above.", Usage: usage}, nil
	}

	switch {
	case strings.Contains(last.Content, "automated security review"):
		return call("c1", "add_finding", map[string]any{
			"severity": "high", "rule_id": "CWE-798", "file": "config.py",
			"line": float64(42), "snippet": "API_KEY = \"sk-live-xxx\"", "title": "Hardcoded API key",
		}, usage), nil
	case strings.Contains(last.Content, "false positive"):
		return call("s1", "suppress_finding", map[string]any{
			"rule_id": "CWE-798", "file": "config.py", "reason": "placeholder in a test fixture",
		}, usage), nil
	case strings.Contains(last.Content, "also check"):
		return call("r1", "rescope_review", map[string]any{"area": "pkg/auth"}, usage), nil
	default:
		return provider.Response{Text: "Here is my explanation.", Usage: usage}, nil
	}
}

func call(id, name string, args map[string]any, u provider.Usage) provider.Response {
	return provider.Response{ToolCalls: []provider.ToolCall{{ID: id, Name: name, Args: args}}, Usage: u}
}

func toolResult(m provider.Message, name string) bool {
	for _, r := range m.ToolResults {
		if r.Name == name {
			return true
		}
	}
	return false
}

// openedPRNum builds a pull_request "opened" delivery body for a given PR
// number and head SHA (the fixed openedPR constant is always #42).
func openedPRNum(number int, headSHA string) string {
	return `{
  "action": "opened",
  "number": ` + strconv.Itoa(number) + `,
  "pull_request": {
    "user": {"login": "alice"},
    "head": {"sha": ` + strconv.Quote(headSHA) + `},
    "base": {"sha": "basesha000"}
  },
  "repository": {"full_name": "argusappsec/argus", "name": "argus", "owner": {"login": "argusappsec"}}
}`
}

// reviewPREvent drives one opened-PR review through the channel.
func reviewPREvent(t *testing.T, s *Server, body string, delivery string) {
	t.Helper()
	b := []byte(body)
	if code := postEvent(t, s, "pull_request", delivery, b, sign(b, testSecret)); code != 200 {
		t.Fatalf("review event status = %d, want 200", code)
	}
}

// commentEvent drives one issue_comment through the channel.
func commentEvent(t *testing.T, s *Server, number int, login, text, delivery string) int {
	t.Helper()
	b := []byte(commentOn(number, login, text))
	return postEvent(t, s, "issue_comment", delivery, b, sign(b, testSecret))
}

func TestChannel_SuppressFindingRemovesFromReviewAndRecordsAdvisory(t *testing.T) {
	host := &fakeHost{
		repos:     []string{installedRepo},
		clonePath: t.TempDir(),
		cloneSHA:  "headsha111",
		diff:      diffCovering("config.py", 40, 5),
	}
	s, dc, _ := testChannel(t, host, &routerProvider{}, true, nil)

	// 1. The PR review posts the finding as an inline comment.
	reviewPREvent(t, s, openedPR, "d1")
	if len(host.reviews) != 1 || len(host.reviews[0].review.Inline) != 1 {
		t.Fatalf("initial review = %+v, want 1 review with 1 inline comment", host.reviews)
	}

	// 2. An analyst accepts it as a false positive in the thread.
	if code := commentEvent(t, s, 42, "bob", "@argus ignore the config.py finding, it's a false positive", "c1"); code != 200 {
		t.Fatalf("comment status = %d, want 200", code)
	}

	// The review is re-posted (replace) WITHOUT the suppressed finding — removed
	// from this PR's review immediately.
	if len(host.reviews) != 2 {
		t.Fatalf("reviews = %d, want 2 (an initial review + the re-post after suppression)", len(host.reviews))
	}
	repost := host.reviews[1]
	if !repost.replace {
		t.Error("the re-post after suppression must replace the prior review (replace=true)")
	}
	if len(repost.review.Inline) != 0 {
		t.Errorf("suppressed finding must be gone from the review, still has %d inline comments", len(repost.review.Inline))
	}

	// The suppression is HARD and LOCAL: recorded in the PR's review state.
	state, err := newPRReviewStore(dc.Home).Load(installedRepo, 42)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Suppressed) != 1 {
		t.Fatalf("PR state suppressed = %v, want exactly one finding", state.Suppressed)
	}

	// The acceptance is ALSO recorded in MEMORY as SOFT advisory — not a mute.
	mem, err := os.ReadFile(dc.Home + "/MEMORY.md")
	if err != nil {
		t.Fatalf("read MEMORY: %v", err)
	}
	memStr := string(mem)
	if !strings.Contains(memStr, "Advisory") || !strings.Contains(memStr, "CWE-798") {
		t.Errorf("MEMORY missing the advisory note:\n%s", memStr)
	}
	if !strings.Contains(memStr, "NOT a global mute") {
		t.Errorf("MEMORY advisory must state it is not a global mute:\n%s", memStr)
	}
}

func TestChannel_SuppressionIsLocalNotGlobalMute(t *testing.T) {
	host := &fakeHost{
		repos:     []string{installedRepo},
		clonePath: t.TempDir(),
		cloneSHA:  "headsha111",
		diff:      diffCovering("config.py", 40, 5),
	}
	s, _, _ := testChannel(t, host, &routerProvider{}, true, nil)

	// Review PR #42 and suppress its finding.
	reviewPREvent(t, s, openedPR, "d1")
	commentEvent(t, s, 42, "bob", "@argus that's a false positive", "c1")

	// A DIFFERENT PR (#43) finds the SAME pattern: it must still be reported.
	// Suppression is local to PR #42, never a content-keyed global mute.
	reviewPREvent(t, s, openedPRNum(43, "headsha222"), "d2")

	last := host.reviews[len(host.reviews)-1]
	if last.number != 43 {
		t.Fatalf("last review target = #%d, want #43", last.number)
	}
	if len(last.review.Inline) != 1 {
		t.Errorf("the same finding on a different PR must still be flagged, got %d inline comments", len(last.review.Inline))
	}
}

func TestChannel_SuppressionSurvivesSynchronize(t *testing.T) {
	host := &fakeHost{
		repos:     []string{installedRepo},
		clonePath: t.TempDir(),
		cloneSHA:  "headsha111",
		diff:      diffCovering("config.py", 40, 5),
	}
	s, _, _ := testChannel(t, host, &routerProvider{}, true, nil)

	reviewPREvent(t, s, openedPR, "d1")
	commentEvent(t, s, 42, "bob", "@argus false positive on the config.py finding", "c1")

	// A new push (synchronize) re-reviews the SAME PR and re-discovers the
	// finding — but the PR-local suppression still drops it from the review.
	sync := strings.Replace(openedPR, `"action": "opened"`, `"action": "synchronize"`, 1)
	reviewPREvent(t, s, sync, "d2")

	last := host.reviews[len(host.reviews)-1]
	if !last.replace {
		t.Error("a synchronize re-review must replace the prior review")
	}
	if len(last.review.Inline) != 0 {
		t.Errorf("a finding suppressed on this PR must stay gone across re-reviews, got %d inline", len(last.review.Inline))
	}
}

func TestChannel_ViewerCannotSuppress(t *testing.T) {
	host := &fakeHost{
		repos:     []string{installedRepo},
		clonePath: t.TempDir(),
		cloneSHA:  "headsha111",
		diff:      diffCovering("config.py", 40, 5),
	}
	s, dc, _ := testChannel(t, host, &routerProvider{}, true, nil)

	reviewPREvent(t, s, openedPR, "d1")

	// carol is a viewer: explain-only. Her suppression attempt is refused at the
	// tool layer, so the finding stays and no re-post happens.
	if code := commentEvent(t, s, 42, "carol", "@argus this is a false positive, drop it", "c1"); code != 200 {
		t.Fatalf("comment status = %d, want 200", code)
	}
	if len(host.reviews) != 1 {
		t.Errorf("a viewer must not be able to re-post (suppress) the review, reviews = %d", len(host.reviews))
	}
	state, err := newPRReviewStore(dc.Home).Load(installedRepo, 42)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Suppressed) != 0 {
		t.Errorf("a viewer must not suppress findings, suppressed = %v", state.Suppressed)
	}
	// She still gets a (refusal-relaying) reply — explain access is unchanged.
	if len(host.comments) != 1 {
		t.Errorf("viewer should still get a threaded reply, comments = %d", len(host.comments))
	}
}

func TestChannel_RescopeRunsFocusedPassNotFullReview(t *testing.T) {
	host := &fakeHost{
		repos:     []string{installedRepo},
		clonePath: t.TempDir(),
		cloneSHA:  "headsha111",
		diff:      diffCovering("config.py", 40, 5),
	}
	s, _, _ := testChannel(t, host, &routerProvider{}, true, nil)

	reviewPREvent(t, s, openedPR, "d1") // one clone at head, one review

	if code := commentEvent(t, s, 42, "bob", "@argus also check the auth module", "c1"); code != 200 {
		t.Fatalf("comment status = %d, want 200", code)
	}

	// The focused pass clones the PR head again (to read the area)…
	if len(host.clones) != 2 {
		t.Fatalf("clones = %d, want 2 (initial review + the focused re-scope checkout)", len(host.clones))
	}
	if host.clones[1].ref != "headsha111" {
		t.Errorf("re-scope must clone the PR head, got ref %q", host.clones[1].ref)
	}
	// …but does NOT post a new review: a re-scope is an additional pass, not a
	// full re-review. It replies in the thread instead.
	if len(host.reviews) != 1 {
		t.Errorf("re-scope must not post another review, reviews = %d", len(host.reviews))
	}
	if len(host.comments) != 1 {
		t.Errorf("re-scope should reply in the thread, comments = %d", len(host.comments))
	}
}

func TestChannel_ViewerCannotRescope(t *testing.T) {
	host := &fakeHost{
		repos:     []string{installedRepo},
		clonePath: t.TempDir(),
		cloneSHA:  "headsha111",
		diff:      diffCovering("config.py", 40, 5),
	}
	s, _, _ := testChannel(t, host, &routerProvider{}, true, nil)

	reviewPREvent(t, s, openedPR, "d1")

	commentEvent(t, s, 42, "carol", "@argus also check the auth module", "c1")

	// The viewer's re-scope is refused at the tool layer: no extra clone.
	if len(host.clones) != 1 {
		t.Errorf("a viewer must not trigger a re-scope checkout, clones = %d", len(host.clones))
	}
}
