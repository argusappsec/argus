package github_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/argusappsec/argus/pkg/codehost"
	"github.com/argusappsec/argus/pkg/codehost/github"
)

// tokenEndpoint registers the App installation-token mint endpoint the minter
// calls before every authenticated request, plus the App-JWT installation
// resolution the CodeHost performs to learn which installation owns a repo
// (ADR 0015): argusappsec/argus resolves to installation 456.
func tokenEndpoint(mux *http.ServeMux) {
	mux.HandleFunc("/app/installations/456/access_tokens", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"token": "ghs_x", "expires_at": "2099-01-01T00:00:00Z"})
	})
	mux.HandleFunc("/repos/argusappsec/argus/installation", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"id": 456})
	})
}

// apiServer stands up token + REST endpoints and records the last comment body.
func apiServer(t *testing.T) (*httptest.Server, *string) {
	t.Helper()
	var lastComment string
	mux := http.NewServeMux()
	tokenEndpoint(mux)
	mux.HandleFunc("/repos/argusappsec/argus/issues/42/comments", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer ghs_x" {
			t.Errorf("auth header = %q, want installation token", got)
		}
		b, _ := io.ReadAll(r.Body)
		var payload struct {
			Body string `json:"body"`
		}
		_ = json.Unmarshal(b, &payload)
		lastComment = payload.Body
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id": 1}`))
	})
	mux.HandleFunc("/installation/repositories", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"repositories": []map[string]any{
				{"full_name": "argusappsec/argus"},
				{"full_name": "argusappsec/other"},
			},
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &lastComment
}

func newTestHost(t *testing.T, srv *httptest.Server) *github.CodeHost {
	t.Helper()
	minter, err := github.NewTokenMinterFromPEM("123", testKeyPEM(t),
		github.WithAPIBase(srv.URL), github.WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatal(err)
	}
	return github.NewCodeHost(t.TempDir(), minter,
		github.WithCodeHostAPIBase(srv.URL), github.WithCodeHostHTTPClient(srv.Client()))
}

func TestCodeHost_PostComment(t *testing.T) {
	srv, lastComment := apiServer(t)
	host := newTestHost(t, srv)

	repo := codehost.Repo{Host: "github.com", Owner: "argusappsec", Name: "argus", FullName: "github.com/argusappsec/argus"}
	if err := host.PostComment(context.Background(), repo, 42, "hello PR"); err != nil {
		t.Fatalf("post comment: %v", err)
	}
	if *lastComment != "hello PR" {
		t.Errorf("posted body = %q, want %q", *lastComment, "hello PR")
	}
}

func TestCodeHost_InstallationRepos(t *testing.T) {
	srv, _ := apiServer(t)
	host := newTestHost(t, srv)

	repo := codehost.Repo{Host: "github.com", Owner: "argusappsec", Name: "argus", FullName: "github.com/argusappsec/argus"}
	repos, err := host.InstallationRepos(context.Background(), repo)
	if err != nil {
		t.Fatalf("installation repos: %v", err)
	}
	want := []string{"github.com/argusappsec/argus", "github.com/argusappsec/other"}
	if strings.Join(repos, ",") != strings.Join(want, ",") {
		t.Errorf("repos = %v, want %v", repos, want)
	}
}

// TestCodeHost_ResolvesInstallationPerRepo proves on-demand work derives the
// installation for a repo via the App JWT (GET /repos/{o}/{r}/installation),
// then mints that installation's token — no pinned installation id (ADR 0015).
func TestCodeHost_ResolvesInstallationPerRepo(t *testing.T) {
	var resolvedWithJWT bool
	var tokenPath string
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/octo/app/installation", func(w http.ResponseWriter, r *http.Request) {
		// Resolution is authenticated with the App JWT, not an installation token.
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("resolution auth = %q, want App JWT bearer", r.Header.Get("Authorization"))
		}
		resolvedWithJWT = true
		_ = json.NewEncoder(w).Encode(map[string]any{"id": 789})
	})
	mux.HandleFunc("/app/installations/789/access_tokens", func(w http.ResponseWriter, _ *http.Request) {
		tokenPath = "789"
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"token": "ghs_789", "expires_at": "2099-01-01T00:00:00Z"})
	})
	mux.HandleFunc("/repos/octo/app/issues/9/comments", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer ghs_789" {
			t.Errorf("comment auth = %q, want the resolved installation's token", got)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":1}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	host := newTestHost(t, srv)

	repo := codehost.Repo{Host: "github.com", Owner: "octo", Name: "app", FullName: "github.com/octo/app"}
	if err := host.PostComment(context.Background(), repo, 9, "hi"); err != nil {
		t.Fatalf("post comment: %v", err)
	}
	if !resolvedWithJWT || tokenPath != "789" {
		t.Errorf("resolvedWithJWT=%v tokenPath=%q, want resolution then installation 789", resolvedWithJWT, tokenPath)
	}
}

// TestCodeHost_NotInstalledError surfaces a clear, repo-named error when the
// App is not installed on the target repo (404 on resolution).
func TestCodeHost_NotInstalledError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/octo/private/installation", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"Not Found"}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	host := newTestHost(t, srv)

	repo := codehost.Repo{Host: "github.com", Owner: "octo", Name: "private", FullName: "github.com/octo/private"}
	_, err := host.InstallationRepos(context.Background(), repo)
	if err == nil || !strings.Contains(err.Error(), "github.com/octo/private") {
		t.Fatalf("err = %v, want a not-installed error naming the repo", err)
	}
}

// TestCodeHost_CloneEmbedsInstallationToken proves the shared client clones a
// (private) repo authenticated: it resolves the repo's installation via the App
// JWT, mints that installation's token, and embeds it into the git remote as
// the x-access-token basic-auth user — the wiring that makes a chat- or
// webhook-triggered clone of a private repo succeed (ADR 0015).
func TestCodeHost_CloneEmbedsInstallationToken(t *testing.T) {
	srv, _ := apiServer(t)
	runs := &fakeRunner{
		onRun: func(args ...string) (string, error) {
			if len(args) > 0 && args[0] == "ls-remote" {
				return "fakesha1234567890abcdef0000000000000000000\tHEAD\n", nil
			}
			if len(args) >= 2 && args[0] == "clone" {
				_ = os.MkdirAll(args[len(args)-1], 0o700)
			}
			return "", nil
		},
	}
	minter, err := github.NewTokenMinterFromPEM("123", testKeyPEM(t),
		github.WithAPIBase(srv.URL), github.WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatal(err)
	}
	host := github.NewCodeHost(t.TempDir(), minter,
		github.WithCodeHostAPIBase(srv.URL), github.WithCodeHostHTTPClient(srv.Client()),
		github.WithCloneRunner(runs))

	repo := codehost.Repo{Host: "github.com", Owner: "argusappsec", Name: "argus", FullName: "github.com/argusappsec/argus"}
	co, err := host.Clone(context.Background(), repo, "")
	if err != nil {
		t.Fatalf("clone: %v", err)
	}
	if co.SHA != "fakesha1234567890abcdef0000000000000000000" {
		t.Errorf("sha = %q", co.SHA)
	}
	sawToken := false
	for _, call := range runs.calls {
		for _, tok := range call {
			if strings.Contains(tok, "x-access-token:ghs_x@github.com/argusappsec/argus") {
				sawToken = true
			}
		}
	}
	if !sawToken {
		t.Errorf("expected git remote to embed the minted installation token, got: %v", runs.calls)
	}
}

// TestCodeHost_SeededInstallationSkipsResolution proves a webhook-seeded
// installation (NoteInstallation) is used directly, without an App-JWT lookup.
func TestCodeHost_SeededInstallationSkipsResolution(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/octo/app/installation", func(http.ResponseWriter, *http.Request) {
		t.Error("resolution endpoint must not be called when the installation is seeded")
	})
	mux.HandleFunc("/app/installations/555/access_tokens", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"token": "ghs_555", "expires_at": "2099-01-01T00:00:00Z"})
	})
	mux.HandleFunc("/repos/octo/app/issues/1/comments", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer ghs_555" {
			t.Errorf("comment auth = %q, want the seeded installation's token", got)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":1}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	host := newTestHost(t, srv)

	repo := codehost.Repo{Host: "github.com", Owner: "octo", Name: "app", FullName: "github.com/octo/app"}
	host.NoteInstallation(repo, "555")
	if err := host.PostComment(context.Background(), repo, 1, "hi"); err != nil {
		t.Fatalf("post comment: %v", err)
	}
}

func TestCodeHost_FetchPRDiff(t *testing.T) {
	mux := http.NewServeMux()
	tokenEndpoint(mux)
	mux.HandleFunc("/repos/argusappsec/argus/pulls/42/files", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[
		  {"filename": "config.py", "status": "modified",
		   "patch": "@@ -40,3 +40,5 @@ def load()\n-old\n+new1\n+new2"},
		  {"filename": "logo.png", "status": "added"}
		]`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	host := newTestHost(t, srv)

	repo := codehost.Repo{Host: "github.com", Owner: "argusappsec", Name: "argus", FullName: "github.com/argusappsec/argus"}
	diff, err := host.FetchPRDiff(context.Background(), repo, 42)
	if err != nil {
		t.Fatalf("fetch PR diff: %v", err)
	}
	if len(diff.Files) != 2 {
		t.Fatalf("files = %d, want 2", len(diff.Files))
	}
	cfg := diff.Files[0]
	if cfg.Path != "config.py" || cfg.Status != "modified" {
		t.Errorf("file[0] = %+v", cfg)
	}
	// The +40,5 hunk header parses to the head-side range, so config.py:42 is a
	// changed line while config.py:46 is past it.
	if !diff.IsChangedLine("config.py", 42) {
		t.Error("config.py:42 should be a changed line (within +40,5)")
	}
	if diff.IsChangedLine("config.py", 46) {
		t.Error("config.py:46 is past the hunk and must not be a changed line")
	}
	// A binary file GitHub omits the patch for yields no hunks.
	if len(diff.Files[1].Hunks) != 0 {
		t.Errorf("binary file should have no hunks, got %d", len(diff.Files[1].Hunks))
	}
}

func TestCodeHost_PostReviewMapsInlineAndSummary(t *testing.T) {
	var inline []map[string]any
	var summaryBody string
	mux := http.NewServeMux()
	tokenEndpoint(mux)
	mux.HandleFunc("/repos/argusappsec/argus/pulls/42/comments", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var payload map[string]any
		_ = json.Unmarshal(b, &payload)
		inline = append(inline, payload)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id": 1}`))
	})
	mux.HandleFunc("/repos/argusappsec/argus/issues/42/comments", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var payload struct {
			Body string `json:"body"`
		}
		_ = json.Unmarshal(b, &payload)
		summaryBody = payload.Body
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id": 2}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	host := newTestHost(t, srv)

	repo := codehost.Repo{Host: "github.com", Owner: "argusappsec", Name: "argus", FullName: "github.com/argusappsec/argus"}
	review := codehost.Review{
		HeadSHA: "headsha111",
		Summary: "Off-diff: bumped lib to a vulnerable version.",
		Inline:  []codehost.InlineComment{{Path: "config.py", Line: 42, Body: "Hardcoded API key"}},
	}
	if err := host.PostReview(context.Background(), repo, 42, review, false); err != nil {
		t.Fatalf("post review: %v", err)
	}

	// The inline finding is a PR review comment pinned to the head SHA, RIGHT side.
	if len(inline) != 1 {
		t.Fatalf("inline comments = %d, want 1", len(inline))
	}
	ic := inline[0]
	if ic["path"] != "config.py" || ic["commit_id"] != "headsha111" || ic["side"] != "RIGHT" {
		t.Errorf("inline payload = %+v", ic)
	}
	if line, _ := ic["line"].(float64); int(line) != 42 {
		t.Errorf("inline line = %v, want 42", ic["line"])
	}
	if body, _ := ic["body"].(string); !strings.Contains(body, "Hardcoded API key") {
		t.Errorf("inline body = %q", ic["body"])
	}
	// The summary is an issue comment carrying the off-diff narrative.
	if !strings.Contains(summaryBody, "Off-diff: bumped lib") {
		t.Errorf("summary body = %q", summaryBody)
	}
}

func TestCodeHost_PostReviewReplaceDeletesPrior(t *testing.T) {
	var deleted []int64
	mux := http.NewServeMux()
	tokenEndpoint(mux)
	// Listing prior PR review comments: one carries the marker, one does not.
	mux.HandleFunc("/repos/argusappsec/argus/pulls/42/comments", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`[
			  {"id": 11, "body": "stale finding\n<!-- argus-review -->"},
			  {"id": 12, "body": "a human's comment"}
			]`))
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id": 1}`))
	})
	mux.HandleFunc("/repos/argusappsec/argus/pulls/comments/11", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deleted = append(deleted, 11)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	// Listing prior issue (summary) comments: one carries the marker.
	mux.HandleFunc("/repos/argusappsec/argus/issues/42/comments", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`[{"id": 21, "body": "old summary\n<!-- argus-review -->"}]`))
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id": 2}`))
	})
	mux.HandleFunc("/repos/argusappsec/argus/issues/comments/21", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deleted = append(deleted, 21)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	host := newTestHost(t, srv)

	repo := codehost.Repo{Host: "github.com", Owner: "argusappsec", Name: "argus", FullName: "github.com/argusappsec/argus"}
	review := codehost.Review{HeadSHA: "headsha111", Summary: "fresh review"}
	if err := host.PostReview(context.Background(), repo, 42, review, true); err != nil {
		t.Fatalf("post review (replace): %v", err)
	}

	// Only the bot's own marked comments are deleted; the human comment (12) is left.
	if len(deleted) != 2 {
		t.Fatalf("deleted = %v, want the two marked comments (11, 21)", deleted)
	}
	got := map[int64]bool{}
	for _, id := range deleted {
		got[id] = true
	}
	if !got[11] || !got[21] {
		t.Errorf("deleted = %v, want 11 and 21", deleted)
	}
}

func TestCodeHost_ParseURL(t *testing.T) {
	srv, _ := apiServer(t)
	host := newTestHost(t, srv)
	repo, err := host.ParseURL("https://github.com/argusappsec/argus")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if repo.FullName != "github.com/argusappsec/argus" || repo.Owner != "argusappsec" {
		t.Errorf("repo = %+v", repo)
	}
}
