package github_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/redcarbon-dev/argus/pkg/codehost"
	"github.com/redcarbon-dev/argus/pkg/codehost/github"
)

// tokenEndpoint registers the App installation-token mint endpoint the minter
// calls before every authenticated request.
func tokenEndpoint(mux *http.ServeMux) {
	mux.HandleFunc("/app/installations/456/access_tokens", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"token": "ghs_x", "expires_at": "2099-01-01T00:00:00Z"})
	})
}

// apiServer stands up token + REST endpoints and records the last comment body.
func apiServer(t *testing.T) (*httptest.Server, *string) {
	t.Helper()
	var lastComment string
	mux := http.NewServeMux()
	tokenEndpoint(mux)
	mux.HandleFunc("/repos/redcarbon-dev/argus/issues/42/comments", func(w http.ResponseWriter, r *http.Request) {
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
				{"full_name": "redcarbon-dev/argus"},
				{"full_name": "redcarbon-dev/other"},
			},
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &lastComment
}

func newTestHost(t *testing.T, srv *httptest.Server) *github.CodeHost {
	t.Helper()
	minter, err := github.NewTokenMinterFromPEM("123", "456", testKeyPEM(t),
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

	repo := codehost.Repo{Host: "github.com", Owner: "redcarbon-dev", Name: "argus", FullName: "github.com/redcarbon-dev/argus"}
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

	repos, err := host.InstallationRepos(context.Background())
	if err != nil {
		t.Fatalf("installation repos: %v", err)
	}
	want := []string{"github.com/redcarbon-dev/argus", "github.com/redcarbon-dev/other"}
	if strings.Join(repos, ",") != strings.Join(want, ",") {
		t.Errorf("repos = %v, want %v", repos, want)
	}
}

func TestCodeHost_FetchPRDiff(t *testing.T) {
	mux := http.NewServeMux()
	tokenEndpoint(mux)
	mux.HandleFunc("/repos/redcarbon-dev/argus/pulls/42/files", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[
		  {"filename": "config.py", "status": "modified",
		   "patch": "@@ -40,3 +40,5 @@ def load()\n-old\n+new1\n+new2"},
		  {"filename": "logo.png", "status": "added"}
		]`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	host := newTestHost(t, srv)

	repo := codehost.Repo{Host: "github.com", Owner: "redcarbon-dev", Name: "argus", FullName: "github.com/redcarbon-dev/argus"}
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
	mux.HandleFunc("/repos/redcarbon-dev/argus/pulls/42/comments", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var payload map[string]any
		_ = json.Unmarshal(b, &payload)
		inline = append(inline, payload)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id": 1}`))
	})
	mux.HandleFunc("/repos/redcarbon-dev/argus/issues/42/comments", func(w http.ResponseWriter, r *http.Request) {
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

	repo := codehost.Repo{Host: "github.com", Owner: "redcarbon-dev", Name: "argus", FullName: "github.com/redcarbon-dev/argus"}
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
	mux.HandleFunc("/repos/redcarbon-dev/argus/pulls/42/comments", func(w http.ResponseWriter, r *http.Request) {
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
	mux.HandleFunc("/repos/redcarbon-dev/argus/pulls/comments/11", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deleted = append(deleted, 11)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	// Listing prior issue (summary) comments: one carries the marker.
	mux.HandleFunc("/repos/redcarbon-dev/argus/issues/42/comments", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`[{"id": 21, "body": "old summary\n<!-- argus-review -->"}]`))
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id": 2}`))
	})
	mux.HandleFunc("/repos/redcarbon-dev/argus/issues/comments/21", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deleted = append(deleted, 21)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	host := newTestHost(t, srv)

	repo := codehost.Repo{Host: "github.com", Owner: "redcarbon-dev", Name: "argus", FullName: "github.com/redcarbon-dev/argus"}
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
	repo, err := host.ParseURL("https://github.com/redcarbon-dev/argus")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if repo.FullName != "github.com/redcarbon-dev/argus" || repo.Owner != "redcarbon-dev" {
		t.Errorf("repo = %+v", repo)
	}
}
