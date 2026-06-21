package github

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/redcarbon-dev/argus/pkg/audit"
	"github.com/redcarbon-dev/argus/pkg/auth"
	"github.com/redcarbon-dev/argus/pkg/budget"
	"github.com/redcarbon-dev/argus/pkg/codehost"
	"github.com/redcarbon-dev/argus/pkg/daemon"
	"github.com/redcarbon-dev/argus/pkg/provider"
	"github.com/redcarbon-dev/argus/pkg/report"
	"github.com/redcarbon-dev/argus/pkg/skill"
	"github.com/redcarbon-dev/argus/pkg/soul"
)

const installedRepo = "github.com/redcarbon-dev/argus"

// fakeHost records writes and clones, and returns a fixed installation repo set.
type fakeHost struct {
	repos     []string
	comments  []postedComment
	postErr   error
	clonePath string
	cloneSHA  string
	clones    []cloneCall
}

type postedComment struct {
	repo   string
	number int
	body   string
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
func (f *fakeHost) InstallationRepos(context.Context) ([]string, error) { return f.repos, nil }

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
	users := "services:\n  - id: github-app\n    role: ci-trigger\n    kind: github-app\n    secret_sha256: " + hex.EncodeToString(sum[:]) + "\n"
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

func TestChannel_OpenedPRRunsReviewAndPostsSummary(t *testing.T) {
	host := &fakeHost{repos: []string{installedRepo}, clonePath: t.TempDir(), cloneSHA: "headsha111"}
	s, dc, auditPath := testChannel(t, host, reviewScript(), true, nil)

	body := []byte(openedPR)
	code := postEvent(t, s, "pull_request", "d1", body, sign(body, testSecret))
	if code != 200 {
		t.Fatalf("status = %d, want 200", code)
	}

	// The PR head is cloned via the installation-token CodeHost at the head SHA.
	if len(host.clones) != 1 || host.clones[0].ref != "headsha111" || host.clones[0].repo != installedRepo {
		t.Fatalf("clones = %+v, want one clone of %s at headsha111", host.clones, installedRepo)
	}

	// A single summary review comment is posted, carrying the agent's findings.
	if len(host.comments) != 1 {
		t.Fatalf("comments = %d, want 1", len(host.comments))
	}
	c := host.comments[0]
	if c.number != 42 || c.repo != installedRepo {
		t.Errorf("comment target = %+v", c)
	}
	if !strings.Contains(c.body, "Hardcoded API key") || !strings.Contains(c.body, "config.py:42") {
		t.Errorf("summary body missing finding details:\n%s", c.body)
	}
	if !strings.Contains(c.body, "One high-severity issue found.") {
		t.Errorf("summary body missing report summary:\n%s", c.body)
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

func TestChannel_CleanReviewPostsNoFindings(t *testing.T) {
	host := &fakeHost{repos: []string{installedRepo}, clonePath: t.TempDir()}
	clean := &scriptedProvider{responses: []provider.Response{{
		ToolCalls: []provider.ToolCall{{ID: "c1", Name: "finalize_report", Args: map[string]any{"summary": "Nothing to flag."}}},
		Usage:     provider.Usage{InputTokens: 10, OutputTokens: 5},
	}}}
	s, _, _ := testChannel(t, host, clean, true, nil)

	body := []byte(openedPR)
	postEvent(t, s, "pull_request", "d1", body, sign(body, testSecret))
	if len(host.comments) != 1 {
		t.Fatalf("comments = %d, want 1", len(host.comments))
	}
	if !strings.Contains(host.comments[0].body, "No security findings") {
		t.Errorf("clean review body:\n%s", host.comments[0].body)
	}
}

func TestChannel_DuplicateDeliveryDeduped(t *testing.T) {
	host := &fakeHost{repos: []string{installedRepo}, clonePath: t.TempDir()}
	s, _, _ := testChannel(t, host, reviewScript(), true, nil)

	body := []byte(openedPR)
	sig := sign(body, testSecret)
	postEvent(t, s, "pull_request", "dup", body, sig)
	postEvent(t, s, "pull_request", "dup", body, sig)
	if len(host.comments) != 1 {
		t.Errorf("comments = %d, want 1 (duplicate delivery must not re-review)", len(host.comments))
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
	if len(host.comments) != 0 {
		t.Errorf("a forged delivery must not post a comment")
	}
}

func TestChannel_AutoEnrollFalseIgnoresUnenabledRepo(t *testing.T) {
	host := &fakeHost{repos: []string{installedRepo}, clonePath: t.TempDir()}
	s, _, auditPath := testChannel(t, host, reviewScript(), false, nil) // installed but not enabled

	body := []byte(openedPR)
	postEvent(t, s, "pull_request", "ne", body, sign(body, testSecret))
	if len(host.comments) != 0 {
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
	host := &fakeHost{repos: []string{installedRepo}, clonePath: t.TempDir()}
	s, _, _ := testChannel(t, host, reviewScript(), false, []string{installedRepo})

	body := []byte(openedPR)
	postEvent(t, s, "pull_request", "en", body, sign(body, testSecret))
	if len(host.comments) != 1 {
		t.Errorf("an explicitly enabled repo must be reviewed even with auto_enroll: false")
	}
}

func TestChannel_CommentNotActedOnYet(t *testing.T) {
	host := &fakeHost{repos: []string{installedRepo}, clonePath: t.TempDir()}
	s, _, _ := testChannel(t, host, reviewScript(), true, nil)

	body := []byte(issueComment)
	code := postEvent(t, s, "issue_comment", "c1", body, sign(body, testSecret))
	if code != 200 {
		t.Errorf("status = %d, want 200", code)
	}
	if len(host.comments) != 0 {
		t.Errorf("comment events are not acted on until the conversational slice")
	}
}

func TestChannel_SynchronizeNotActedOnYet(t *testing.T) {
	host := &fakeHost{repos: []string{installedRepo}, clonePath: t.TempDir()}
	s, _, _ := testChannel(t, host, reviewScript(), true, nil)

	body := []byte(strings.Replace(openedPR, `"action": "opened"`, `"action": "synchronize"`, 1))
	postEvent(t, s, "pull_request", "sync", body, sign(body, testSecret))
	if len(host.comments) != 0 {
		t.Errorf("synchronize is handled in the diff-aware slice, not slice 2")
	}
}
