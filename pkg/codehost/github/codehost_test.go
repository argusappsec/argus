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

// apiServer stands up token + REST endpoints and records the last comment body.
func apiServer(t *testing.T) (*httptest.Server, *string) {
	t.Helper()
	var lastComment string
	mux := http.NewServeMux()
	mux.HandleFunc("/app/installations/456/access_tokens", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"token": "ghs_x", "expires_at": "2099-01-01T00:00:00Z"})
	})
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
