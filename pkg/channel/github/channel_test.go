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
	"testing"

	"github.com/redcarbon-dev/argus/pkg/audit"
	"github.com/redcarbon-dev/argus/pkg/auth"
	"github.com/redcarbon-dev/argus/pkg/codehost"
	"github.com/redcarbon-dev/argus/pkg/daemon"
)

const installedRepo = "github.com/redcarbon-dev/argus"

// fakeHost records writes and returns a fixed installation repo set.
type fakeHost struct {
	repos    []string
	comments []postedComment
	postErr  error
}

type postedComment struct {
	repo   string
	number int
	body   string
}

func (f *fakeHost) ParseURL(raw string) (codehost.Repo, error) { return codehost.Repo{}, nil }
func (f *fakeHost) Clone(context.Context, codehost.Repo, string) (codehost.Checkout, error) {
	return codehost.Checkout{}, nil
}
func (f *fakeHost) PostComment(_ context.Context, repo codehost.Repo, number int, body string) error {
	if f.postErr != nil {
		return f.postErr
	}
	f.comments = append(f.comments, postedComment{repo.FullName, number, body})
	return nil
}
func (f *fakeHost) InstallationRepos(context.Context) ([]string, error) { return f.repos, nil }

// testChannel builds a channel over a temp home with a github-app Service whose
// secret hash matches testSecret. enabled toggles auto_enroll.
func testChannel(t *testing.T, host codehost.CodeHost, autoEnroll bool, enabledRepos []string) (*Server, string) {
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
	dc := &daemon.Context{Home: home, Auth: auth.NewResolver(usersPath), Audit: aud}
	srv := NewServer(dc, host, Options{
		Addr:          ":0",
		WebhookSecret: testSecret,
		AutoEnroll:    autoEnroll,
		EnabledRepos:  enabledRepos,
	})
	return srv, auditPath
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

func TestChannel_OpenedPRPostsAcknowledgment(t *testing.T) {
	host := &fakeHost{repos: []string{installedRepo}}
	s, auditPath := testChannel(t, host, true, nil)

	body := []byte(openedPR)
	code := postEvent(t, s, "pull_request", "d1", body, sign(body, testSecret))
	if code != 200 {
		t.Fatalf("status = %d, want 200", code)
	}
	if len(host.comments) != 1 {
		t.Fatalf("comments = %d, want 1", len(host.comments))
	}
	c := host.comments[0]
	if c.number != 42 || c.repo != installedRepo || c.body != ackBody {
		t.Errorf("comment = %+v", c)
	}

	// Audit attributes the trigger to the App-installation Service, PR author metadata.
	ev := findEvent(auditEvents(t, auditPath), "github_pr_acknowledged")
	if ev == nil {
		t.Fatal("no github_pr_acknowledged audit event")
	}
	if ev.Data["principal"] != "github-app" {
		t.Errorf("principal = %v, want github-app", ev.Data["principal"])
	}
	if ev.Data["pr_author"] != "alice" {
		t.Errorf("pr_author = %v, want alice (metadata)", ev.Data["pr_author"])
	}
}

func TestChannel_DuplicateDeliveryDeduped(t *testing.T) {
	host := &fakeHost{repos: []string{installedRepo}}
	s, _ := testChannel(t, host, true, nil)

	body := []byte(openedPR)
	sig := sign(body, testSecret)
	postEvent(t, s, "pull_request", "dup", body, sig)
	postEvent(t, s, "pull_request", "dup", body, sig)
	if len(host.comments) != 1 {
		t.Errorf("comments = %d, want 1 (duplicate delivery must not re-ack)", len(host.comments))
	}
}

func TestChannel_TamperedSignatureRejected(t *testing.T) {
	host := &fakeHost{repos: []string{installedRepo}}
	s, _ := testChannel(t, host, true, nil)

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
	host := &fakeHost{repos: []string{installedRepo}}
	s, auditPath := testChannel(t, host, false, nil) // installed but not enabled

	body := []byte(openedPR)
	postEvent(t, s, "pull_request", "ne", body, sign(body, testSecret))
	if len(host.comments) != 0 {
		t.Errorf("auto_enroll: false on an unenabled repo must not ack")
	}
	if findEvent(auditEvents(t, auditPath), "github_pr_ignored") == nil {
		t.Error("expected a github_pr_ignored audit event")
	}
}

func TestChannel_AutoEnrollFalseActsOnEnabledRepo(t *testing.T) {
	host := &fakeHost{repos: []string{installedRepo}}
	s, _ := testChannel(t, host, false, []string{installedRepo})

	body := []byte(openedPR)
	postEvent(t, s, "pull_request", "en", body, sign(body, testSecret))
	if len(host.comments) != 1 {
		t.Errorf("an explicitly enabled repo must be acked even with auto_enroll: false")
	}
}

func TestChannel_CommentNotActedOnInSliceOne(t *testing.T) {
	host := &fakeHost{repos: []string{installedRepo}}
	s, _ := testChannel(t, host, true, nil)

	body := []byte(issueComment)
	code := postEvent(t, s, "issue_comment", "c1", body, sign(body, testSecret))
	if code != 200 {
		t.Errorf("status = %d, want 200", code)
	}
	if len(host.comments) != 0 {
		t.Errorf("comment events are not acted on in slice 1")
	}
}
