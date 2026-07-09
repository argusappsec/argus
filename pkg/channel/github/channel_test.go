package github

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/argusappsec/argus/pkg/audit"
	"github.com/argusappsec/argus/pkg/auth"
	"github.com/argusappsec/argus/pkg/budget"
	"github.com/argusappsec/argus/pkg/codehost"
	"github.com/argusappsec/argus/pkg/daemon"
	"github.com/argusappsec/argus/pkg/provider"
	"github.com/argusappsec/argus/pkg/report"
	"github.com/argusappsec/argus/pkg/skill"
	"github.com/argusappsec/argus/pkg/soul"
)

const installedRepo = "github.com/argusappsec/argus"

// fakeHost records writes and clones, returns a fixed installation repo set,
// and serves a configurable PR diff so the channel's inline-vs-summary
// placement can be exercised without a live GitHub API.
type fakeHost struct {
	repos     []string
	comments  []postedComment
	reviews   []postedReview
	diff      codehost.PRDiff
	postErr   error
	clonePath string
	cloneSHA  string
	clones    []cloneCall
	noted     map[string]string // repo full name → installation id seeded from the event
}

type postedComment struct {
	repo   string
	number int
	body   string
}

// postedReview captures one PostReview call for assertions.
type postedReview struct {
	repo    string
	number  int
	review  codehost.Review
	replace bool
}

type cloneCall struct {
	repo string
	ref  string
}

func (f *fakeHost) ParseURL(raw string) (codehost.Repo, error) { return codehost.Repo{}, nil }
func (f *fakeHost) Clone(_ context.Context, repo codehost.Repo, ref string) (codehost.Checkout, error) {
	f.clones = append(f.clones, cloneCall{repo.FullName, ref})
	sha := f.cloneSHA
	if sha == "" {
		sha = ref
	}
	return codehost.Checkout{Path: f.clonePath, SHA: sha}, nil
}
func (f *fakeHost) PostComment(_ context.Context, repo codehost.Repo, number int, body string) error {
	if f.postErr != nil {
		return f.postErr
	}
	f.comments = append(f.comments, postedComment{repo.FullName, number, body})
	return nil
}
func (f *fakeHost) FetchPRDiff(context.Context, codehost.Repo, int) (codehost.PRDiff, error) {
	return f.diff, nil
}
func (f *fakeHost) PostReview(_ context.Context, repo codehost.Repo, number int, review codehost.Review, replace bool) error {
	if f.postErr != nil {
		return f.postErr
	}
	f.reviews = append(f.reviews, postedReview{repo.FullName, number, review, replace})
	return nil
}
func (f *fakeHost) InstallationRepos(context.Context, codehost.Repo) ([]string, error) {
	return f.repos, nil
}
func (f *fakeHost) NoteInstallation(repo codehost.Repo, installationID string) {
	if f.noted == nil {
		f.noted = map[string]string{}
	}
	f.noted[repo.FullName] = installationID
}

// diffCovering builds a PRDiff whose single file's hunk covers [start, start+n).
func diffCovering(path string, start, n int) codehost.PRDiff {
	return codehost.PRDiff{Files: []codehost.ChangedFile{{
		Path:   path,
		Status: "modified",
		Hunks:  []codehost.Hunk{{NewStart: start, NewLines: n}},
	}}}
}

// scriptedProvider returns canned responses in order; the last response is
// repeated once the script runs out (so the async memory curator terminates).
type scriptedProvider struct {
	mu        sync.Mutex
	responses []provider.Response
	calls     int
}

func (p *scriptedProvider) Generate(_ context.Context, _ provider.Request) (provider.Response, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	i := p.calls
	if i >= len(p.responses) {
		i = len(p.responses) - 1
	}
	p.calls++
	return p.responses[i], nil
}

// reviewScript drives the agent to record one finding and finalize.
func reviewScript() *scriptedProvider {
	usage := provider.Usage{InputTokens: 100, OutputTokens: 50}
	return &scriptedProvider{responses: []provider.Response{
		{
			ToolCalls: []provider.ToolCall{{
				ID:   "c1",
				Name: "add_finding",
				Args: map[string]any{
					"severity": "high",
					"rule_id":  "CWE-798",
					"file":     "config.py",
					"line":     float64(42),
					"snippet":  "API_KEY = \"sk-live-xxx\"",
					"title":    "Hardcoded API key",
				},
			}},
			Usage: usage,
		},
		{
			ToolCalls: []provider.ToolCall{{
				ID:   "c2",
				Name: "finalize_report",
				Args: map[string]any{"summary": "One high-severity issue found."},
			}},
			Usage: usage,
		},
	}}
}

// testChannel builds a channel over a temp home with a github-app Service whose
// secret hash matches testSecret, and a full daemon Context (scripted provider,
// session manager, report writer) so dispatch can run a real review.
func testChannel(t *testing.T, host codehost.CodeHost, prov provider.Provider, autoEnroll bool, enabledRepos []string) (*Server, *daemon.Context, string) {
	t.Helper()
	home := t.TempDir()
	sum := sha256.Sum256([]byte(testSecret))
	users := "services:\n  - id: github-app\n    role: ci-trigger\n    kind: github-app\n    secret_sha256: " + hex.EncodeToString(sum[:]) + "\n" +
		"persons:\n  - id: bob\n    role: analyst\n    identities:\n      - github:bob\n" +
		"  - id: carol\n    role: viewer\n    identities:\n      - github:carol\n"
	usersPath := filepath.Join(home, "users.yaml")
	if err := os.WriteFile(usersPath, []byte(users), 0o600); err != nil {
		t.Fatal(err)
	}
	auditPath := filepath.Join(home, "audit.log.jsonl")
	aud, err := audit.NewLogger(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = aud.Close() })

	dc := &daemon.Context{
		Home:         home,
		DefaultModel: "gemini-2.5-flash",
		Pricing:      budget.Pricing{"gemini-2.5-flash": {InputUSDPer1M: 1, OutputUSDPer1M: 2}},
		Auth:         auth.NewResolver(usersPath),
		Audit:        aud,
		Reports:      report.NewWriter(filepath.Join(home, "reports")),
		Skills:       skill.NewCatalog(skill.Builtin(), filepath.Join(home, "skills")),
		NewProvider: func(context.Context, string) (provider.Provider, error) {
			return prov, nil
		},
		LoadSoul:   func() (*soul.Soul, error) { return &soul.Soul{}, nil },
		LoadMemory: func() (string, error) { return "", nil },
	}
	dc.Sessions = daemon.NewSessionManager(dc, 4)
	t.Cleanup(func() { dc.Sessions.Drain(2 * time.Second) })

	srv := NewServer(dc, host, Options{
		Addr:          ":0",
		WebhookSecret: testSecret,
		AutoEnroll:    autoEnroll,
		EnabledRepos:  enabledRepos,
	})
	return srv, dc, auditPath
}

func postEvent(t *testing.T, s *Server, eventType, delivery string, body []byte, sig string) int {
	t.Helper()
	req := httptest.NewRequest("POST", "/webhook", strings.NewReader(string(body)))
	req.Header.Set("X-GitHub-Event", eventType)
	req.Header.Set("X-GitHub-Delivery", delivery)
	req.Header.Set("X-Hub-Signature-256", sig)
	rec := httptest.NewRecorder()
	s.handle(rec, req)
	return rec.Code
}

func auditEvents(t *testing.T, path string) []audit.Event {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []audit.Event
	for line := range strings.SplitSeq(strings.TrimSpace(string(b)), "\n") {
		if line == "" {
			continue
		}
		var e audit.Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("parse audit line: %v", err)
		}
		out = append(out, e)
	}
	return out
}

func findEvent(events []audit.Event, typ string) *audit.Event {
	for i := range events {
		if events[i].Type == typ {
			return &events[i]
		}
	}
	return nil
}

func TestChannel_OpenedPRPostsInlineCommentOnChangedLine(t *testing.T) {
	// The finding at config.py:42 falls inside the PR's changed hunk, so it is
	// placed as an inline review comment, not in the summary body.
	host := &fakeHost{
		repos:     []string{installedRepo},
		clonePath: t.TempDir(),
		cloneSHA:  "headsha111",
		diff:      diffCovering("config.py", 40, 5),
	}
	s, dc, auditPath := testChannel(t, host, reviewScript(), true, nil)

	body := []byte(openedPR)
	code := postEvent(t, s, "pull_request", "d1", body, sign(body, testSecret))
	if code != 200 {
		t.Fatalf("status = %d, want 200", code)
	}

	// The installation the App acts as is taken from the event payload and
	// seeded onto the CodeHost (ADR 0015) — no pinned installation id.
	if host.noted[installedRepo] != "987654" {
		t.Errorf("seeded installation = %q, want 987654 from the event", host.noted[installedRepo])
	}

	// The PR head is cloned via the installation-token CodeHost at the head SHA.
	if len(host.clones) != 1 || host.clones[0].ref != "headsha111" || host.clones[0].repo != installedRepo {
		t.Fatalf("clones = %+v, want one clone of %s at headsha111", host.clones, installedRepo)
	}

	// One review is posted (not a synchronize replace).
	if len(host.reviews) != 1 {
		t.Fatalf("reviews = %d, want 1", len(host.reviews))
	}
	rv := host.reviews[0]
	if rv.number != 42 || rv.repo != installedRepo || rv.replace {
		t.Errorf("review target = %+v (replace=%v)", rv, rv.replace)
	}
	if rv.review.HeadSHA != "headsha111" {
		t.Errorf("review head sha = %q, want headsha111", rv.review.HeadSHA)
	}

	// The finding on the changed line is an inline comment on config.py:42.
	if len(rv.review.Inline) != 1 {
		t.Fatalf("inline comments = %d, want 1", len(rv.review.Inline))
	}
	ic := rv.review.Inline[0]
	if ic.Path != "config.py" || ic.Line != 42 {
		t.Errorf("inline location = %s:%d, want config.py:42", ic.Path, ic.Line)
	}
	if !strings.Contains(ic.Body, "Hardcoded API key") {
		t.Errorf("inline body missing finding title:\n%s", ic.Body)
	}

	// The summary body carries the agent narrative and points to the inline
	// comment, but does not re-list the on-diff finding's location.
	if !strings.Contains(rv.review.Summary, "One high-severity issue found.") {
		t.Errorf("summary missing report summary:\n%s", rv.review.Summary)
	}
	if strings.Contains(rv.review.Summary, "config.py:42") {
		t.Errorf("summary must not re-list the inline finding location:\n%s", rv.review.Summary)
	}

	// The review is attributed to the App-installation Service, PR author metadata.
	ev := findEvent(auditEvents(t, auditPath), "github_pr_reviewed")
	if ev == nil {
		t.Fatal("no github_pr_reviewed audit event")
	}
	if ev.Data["principal"] != "github-app" {
		t.Errorf("principal = %v, want github-app", ev.Data["principal"])
	}
	if ev.Data["pr_author"] != "alice" {
		t.Errorf("pr_author = %v, want alice (metadata)", ev.Data["pr_author"])
	}

	// The Report is persisted to disk under the PR head SHA.
	reportPath := dc.Reports.PathFor(installedRepo, "headsha111")
	if _, err := os.Stat(reportPath); err != nil {
		t.Errorf("report not persisted at %s: %v", reportPath, err)
	}
}

func TestChannel_OffDiffFindingGoesToSummaryNotInline(t *testing.T) {
	// The finding at config.py:42 is causally related but NOT on a changed line
	// (the diff touches a different file), so it lands in the summary body —
	// GitHub inline comments can only attach to the diff.
	host := &fakeHost{
		repos:     []string{installedRepo},
		clonePath: t.TempDir(),
		cloneSHA:  "headsha111",
		diff:      diffCovering("other.py", 1, 3),
	}
	s, _, _ := testChannel(t, host, reviewScript(), true, nil)

	body := []byte(openedPR)
	postEvent(t, s, "pull_request", "d1", body, sign(body, testSecret))

	if len(host.reviews) != 1 {
		t.Fatalf("reviews = %d, want 1", len(host.reviews))
	}
	rv := host.reviews[0]
	if len(rv.review.Inline) != 0 {
		t.Errorf("off-diff finding must not be an inline comment, got %d", len(rv.review.Inline))
	}
	if !strings.Contains(rv.review.Summary, "Hardcoded API key") || !strings.Contains(rv.review.Summary, "config.py:42") {
		t.Errorf("summary must carry the off-diff finding:\n%s", rv.review.Summary)
	}
}

func TestChannel_CleanReviewPostsNoFindings(t *testing.T) {
	host := &fakeHost{repos: []string{installedRepo}, clonePath: t.TempDir(), diff: diffCovering("config.py", 40, 5)}
	clean := &scriptedProvider{responses: []provider.Response{{
		ToolCalls: []provider.ToolCall{{ID: "c1", Name: "finalize_report", Args: map[string]any{"summary": "Nothing to flag."}}},
		Usage:     provider.Usage{InputTokens: 10, OutputTokens: 5},
	}}}
	s, _, _ := testChannel(t, host, clean, true, nil)

	body := []byte(openedPR)
	postEvent(t, s, "pull_request", "d1", body, sign(body, testSecret))
	if len(host.reviews) != 1 {
		t.Fatalf("reviews = %d, want 1", len(host.reviews))
	}
	rv := host.reviews[0]
	if len(rv.review.Inline) != 0 {
		t.Errorf("clean review must have no inline comments, got %d", len(rv.review.Inline))
	}
	if !strings.Contains(rv.review.Summary, "No security findings") {
		t.Errorf("clean review summary:\n%s", rv.review.Summary)
	}
}

func TestChannel_SynchronizeReplacesPriorReview(t *testing.T) {
	host := &fakeHost{repos: []string{installedRepo}, clonePath: t.TempDir(), cloneSHA: "headsha111", diff: diffCovering("config.py", 40, 5)}
	s, _, _ := testChannel(t, host, reviewScript(), true, nil)

	body := []byte(strings.Replace(openedPR, `"action": "opened"`, `"action": "synchronize"`, 1))
	postEvent(t, s, "pull_request", "sync", body, sign(body, testSecret))

	if len(host.reviews) != 1 {
		t.Fatalf("reviews = %d, want 1", len(host.reviews))
	}
	if !host.reviews[0].replace {
		t.Error("a synchronize event must replace the bot's prior review (replace=true)")
	}
}

func TestChannel_DuplicateDeliveryDeduped(t *testing.T) {
	host := &fakeHost{repos: []string{installedRepo}, clonePath: t.TempDir(), diff: diffCovering("config.py", 40, 5)}
	s, _, _ := testChannel(t, host, reviewScript(), true, nil)

	body := []byte(openedPR)
	sig := sign(body, testSecret)
	postEvent(t, s, "pull_request", "dup", body, sig)
	postEvent(t, s, "pull_request", "dup", body, sig)
	if len(host.reviews) != 1 {
		t.Errorf("reviews = %d, want 1 (duplicate delivery must not re-review)", len(host.reviews))
	}
}

func TestChannel_TamperedSignatureRejected(t *testing.T) {
	host := &fakeHost{repos: []string{installedRepo}, clonePath: t.TempDir()}
	s, _, _ := testChannel(t, host, reviewScript(), true, nil)

	body := []byte(openedPR)
	code := postEvent(t, s, "pull_request", "bad", body, sign(body, "wrong-secret"))
	if code != 401 {
		t.Errorf("status = %d, want 401", code)
	}
	if len(host.reviews) != 0 {
		t.Errorf("a forged delivery must not post a review")
	}
}

func TestChannel_AutoEnrollFalseIgnoresUnenabledRepo(t *testing.T) {
	host := &fakeHost{repos: []string{installedRepo}, clonePath: t.TempDir()}
	s, _, auditPath := testChannel(t, host, reviewScript(), false, nil) // installed but not enabled

	body := []byte(openedPR)
	postEvent(t, s, "pull_request", "ne", body, sign(body, testSecret))
	if len(host.reviews) != 0 {
		t.Errorf("auto_enroll: false on an unenabled repo must not review")
	}
	if len(host.clones) != 0 {
		t.Errorf("an ignored repo must not be cloned")
	}
	if findEvent(auditEvents(t, auditPath), "github_pr_ignored") == nil {
		t.Error("expected a github_pr_ignored audit event")
	}
}

func TestChannel_AutoEnrollFalseActsOnEnabledRepo(t *testing.T) {
	host := &fakeHost{repos: []string{installedRepo}, clonePath: t.TempDir(), diff: diffCovering("config.py", 40, 5)}
	s, _, _ := testChannel(t, host, reviewScript(), false, []string{installedRepo})

	body := []byte(openedPR)
	postEvent(t, s, "pull_request", "en", body, sign(body, testSecret))
	if len(host.reviews) != 1 {
		t.Errorf("an explicitly enabled repo must be reviewed even with auto_enroll: false")
	}
}

// replyScript drives a conversational turn: the agent emits one text reply
// (no tool calls), which the channel posts back in the thread.
func replyScript(text string) *scriptedProvider {
	return &scriptedProvider{responses: []provider.Response{
		{Text: text, Usage: provider.Usage{InputTokens: 20, OutputTokens: 10}},
	}}
}

// commentOn builds an issue_comment delivery body for the given PR number,
// commenter login, and comment text.
func commentOn(number int, login, text string) string {
	return `{
  "action": "created",
  "issue": {"number": ` + strconv.Itoa(number) + `},
  "comment": {"body": ` + strconv.Quote(text) + `, "user": {"login": ` + strconv.Quote(login) + `}},
  "repository": {"full_name": "argusappsec/argus", "name": "argus", "owner": {"login": "argusappsec"}}
}`
}

func TestChannel_MentionFromResolvedPersonGetsThreadedReply(t *testing.T) {
	host := &fakeHost{repos: []string{installedRepo}, clonePath: t.TempDir()}
	s, _, auditPath := testChannel(t, host, replyScript("The hardcoded key should move to an env var."), true, nil)

	body := []byte(commentOn(42, "bob", "@argus explain this"))
	code := postEvent(t, s, "issue_comment", "c1", body, sign(body, testSecret))
	if code != 200 {
		t.Fatalf("status = %d, want 200", code)
	}

	// The agent's answer is posted back as a threaded comment on the PR.
	if len(host.comments) != 1 {
		t.Fatalf("comments = %d, want 1", len(host.comments))
	}
	c := host.comments[0]
	if c.number != 42 || c.repo != installedRepo {
		t.Errorf("reply target = %s#%d, want %s#42", c.repo, c.number, installedRepo)
	}
	if !strings.Contains(c.body, "move to an env var") {
		t.Errorf("reply body missing agent answer:\n%s", c.body)
	}

	// The turn is attributed to the resolved Person with their Role.
	ev := findEvent(auditEvents(t, auditPath), "github_comment_replied")
	if ev == nil {
		t.Fatal("no github_comment_replied audit event")
	}
	if ev.Data["principal"] != "bob" || ev.Data["role"] != "analyst" {
		t.Errorf("attribution = principal %v / role %v, want bob / analyst", ev.Data["principal"], ev.Data["role"])
	}
}

func TestChannel_PersonaNameMentionGetsThreadedReply(t *testing.T) {
	// An instance deployed under the persona name "Ercole" answers a comment
	// that tags @Ercole (as well as @argus), proving the name is wired from the
	// channel Options through to the deterministic mention match.
	host := &fakeHost{repos: []string{installedRepo}, clonePath: t.TempDir()}
	_, dc, _ := testChannel(t, host, replyScript("Move that key to an env var."), true, nil)
	s := NewServer(dc, host, Options{
		Addr:          ":0",
		WebhookSecret: testSecret,
		AutoEnroll:    true,
		PersonaName:   "Ercole",
	})

	body := []byte(commentOn(42, "bob", "@Ercole explain this"))
	code := postEvent(t, s, "issue_comment", "c1", body, sign(body, testSecret))
	if code != 200 {
		t.Fatalf("status = %d, want 200", code)
	}
	if len(host.comments) != 1 {
		t.Fatalf("comments = %d, want 1 (a persona-name mention must be answered)", len(host.comments))
	}
	if !strings.Contains(host.comments[0].body, "env var") {
		t.Errorf("reply body missing agent answer:\n%s", host.comments[0].body)
	}
}

func TestChannel_CommentWithoutMentionSilentlyIgnored(t *testing.T) {
	host := &fakeHost{repos: []string{installedRepo}, clonePath: t.TempDir()}
	s, _, _ := testChannel(t, host, replyScript("should not run"), true, nil)

	body := []byte(commentOn(42, "bob", "looks good to me, merging"))
	code := postEvent(t, s, "issue_comment", "c1", body, sign(body, testSecret))
	if code != 200 {
		t.Errorf("status = %d, want 200", code)
	}
	if len(host.comments) != 0 {
		t.Errorf("a comment without @argus must not get a reply, got %d", len(host.comments))
	}
}

func TestChannel_MentionFromUnresolvedLoginSilentlyIgnored(t *testing.T) {
	host := &fakeHost{repos: []string{installedRepo}, clonePath: t.TempDir()}
	s, _, auditPath := testChannel(t, host, replyScript("should not run"), true, nil)

	// "stranger" has no Person entry: @argus or not, the comment is ignored.
	body := []byte(commentOn(42, "stranger", "@argus explain this"))
	code := postEvent(t, s, "issue_comment", "c1", body, sign(body, testSecret))
	if code != 200 {
		t.Errorf("status = %d, want 200", code)
	}
	if len(host.comments) != 0 {
		t.Errorf("an unresolved commenter must not get a reply, got %d", len(host.comments))
	}
	if findEvent(auditEvents(t, auditPath), "github_comment_ignored") == nil {
		t.Error("expected a github_comment_ignored audit event for the unresolved login")
	}
}

func TestChannel_CommentSharesPRSessionIdentityAndContext(t *testing.T) {
	// A PR review runs first, then a @argus comment on the same PR. The comment
	// turn must re-attach to the review's Session (keyed by repo + PR number)
	// and see the review context via the on-disk conversation log.
	prov := &scriptedProvider{responses: []provider.Response{
		reviewScript().responses[0], // add_finding
		reviewScript().responses[1], // finalize_report
		{Text: "That config.py finding is a real hardcoded secret.", Usage: provider.Usage{InputTokens: 20, OutputTokens: 10}},
	}}
	host := &fakeHost{repos: []string{installedRepo}, clonePath: t.TempDir(), cloneSHA: "headsha111", diff: diffCovering("config.py", 40, 5)}
	s, dc, _ := testChannel(t, host, prov, true, nil)

	review := []byte(openedPR)
	postEvent(t, s, "pull_request", "d1", review, sign(review, testSecret))

	comment := []byte(commentOn(42, "bob", "@argus explain the config.py finding"))
	postEvent(t, s, "issue_comment", "c1", comment, sign(comment, testSecret))

	if len(host.comments) != 1 {
		t.Fatalf("comments = %d, want 1", len(host.comments))
	}

	// Both the review seed and the comment request live in ONE conversation log,
	// keyed by the PR's stable session identity — that is the shared continuity.
	id := daemon.SessionID("github", "github.com/argusappsec/argus#42")
	log, err := os.ReadFile(filepath.Join(dc.Home, "conversations", id+".jsonl"))
	if err != nil {
		t.Fatalf("read conversation log: %v", err)
	}
	if !strings.Contains(string(log), "automated security review of pull request #42") {
		t.Error("comment turn's session is missing the review seed (no shared identity/context)")
	}
	if !strings.Contains(string(log), "explain the config.py finding") {
		t.Error("comment request was not appended to the PR's conversation log")
	}
}
