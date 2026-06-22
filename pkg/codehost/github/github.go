// Package github clones GitHub repositories into a content-addressed cache.
//
// The cache layout is rooted at one directory per (owner, repo, sha):
//
//	<root>/<owner>__<repo>/<sha>/
//
// A subsequent Clone with the same resolved SHA reuses the existing checkout
// instead of re-fetching. The actual git invocations are abstracted behind a
// Runner so tests can drive the cloner without network access.
package github

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// URL is a parsed GitHub repository reference.
type URL struct {
	Host     string
	Owner    string
	Name     string
	FullName string // "github.com/<owner>/<name>"
}

// ParseURL accepts forms like:
//   - https://github.com/owner/repo
//   - https://github.com/owner/repo.git
//   - github.com/owner/repo
//
// Other hosts and malformed refs are rejected.
func ParseURL(raw string) (URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return URL{}, fmt.Errorf("empty URL")
	}
	s := raw
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return URL{}, fmt.Errorf("parse URL: %w", err)
	}
	if u.Host != "github.com" {
		return URL{}, fmt.Errorf("only github.com is supported, got %q", u.Host)
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return URL{}, fmt.Errorf("URL must be of the form github.com/<owner>/<repo>: %q", raw)
	}
	owner, name := parts[0], strings.TrimSuffix(parts[1], ".git")
	return URL{
		Host:     u.Host,
		Owner:    owner,
		Name:     name,
		FullName: u.Host + "/" + owner + "/" + name,
	}, nil
}

// Runner abstracts execution of git commands so tests can stub them out.
// dir is the working directory; args are passed to git verbatim.
type Runner interface {
	Run(ctx context.Context, dir string, args ...string) (string, error)
}

// Cloner produces local checkouts cached by resolved SHA.
type Cloner struct {
	root   string
	runner Runner

	// auth, when set, yields a short-lived installation token embedded into
	// the clone/ls-remote URL so private repos the App can access succeed
	// (ADR 0008). Nil means anonymous HTTPS (public repos only).
	auth func(ctx context.Context) (string, error)
}

// NewCloner returns a Cloner that uses the system `git` binary.
func NewCloner(root string) *Cloner {
	return NewClonerWithRunner(root, execRunner{})
}

// NewClonerWithRunner returns a Cloner using a custom Runner (tests).
func NewClonerWithRunner(root string, r Runner) *Cloner {
	return &Cloner{root: root, runner: r}
}

// WithAuth returns a Cloner that authenticates git operations with the token
// produced by auth (an installation token). The receiver is not mutated.
func (c *Cloner) WithAuth(auth func(ctx context.Context) (string, error)) *Cloner {
	clone := *c
	clone.auth = auth
	return &clone
}

// remoteURL builds the https remote for u, embedding an installation token as
// the x-access-token basic-auth user when this Cloner is authenticated.
func (c *Cloner) remoteURL(ctx context.Context, u URL) (string, error) {
	if c.auth == nil {
		return "https://github.com/" + u.Owner + "/" + u.Name + ".git", nil
	}
	token, err := c.auth(ctx)
	if err != nil {
		return "", fmt.Errorf("github: installation token: %w", err)
	}
	return "https://x-access-token:" + token + "@github.com/" + u.Owner + "/" + u.Name + ".git", nil
}

// Checkout is the local result of a successful Clone.
type Checkout struct {
	Path string // absolute path on disk
	SHA  string // resolved commit SHA
}

// Clone ensures a local checkout of u@ref exists under the cache root and
// returns it. If ref is empty, the remote default HEAD is used.
//
// Strategy:
//  1. Resolve ref to a SHA up-front via `git ls-remote` (or trust ref as a
//     SHA if it already looks like one). This avoids redundant network work.
//  2. If <root>/<owner>__<repo>/<sha>/ exists, return it (cache hit).
//  3. Otherwise shallow-clone into a staging dir, then atomically rename
//     into place.
func (c *Cloner) Clone(ctx context.Context, u URL, ref string) (Checkout, error) {
	repoDir := filepath.Join(c.root, u.Owner+"__"+u.Name)
	if err := os.MkdirAll(repoDir, 0o700); err != nil {
		return Checkout{}, fmt.Errorf("mkdir cache: %w", err)
	}

	sha, err := c.resolveSHA(ctx, u, ref)
	if err != nil {
		return Checkout{}, err
	}

	finalDir := filepath.Join(repoDir, sha)
	if _, err := os.Stat(finalDir); err == nil {
		return Checkout{Path: finalDir, SHA: sha}, nil // cache hit
	}

	stagingDir, err := os.MkdirTemp(repoDir, "staging-")
	if err != nil {
		return Checkout{}, fmt.Errorf("mkdir staging: %w", err)
	}
	defer os.RemoveAll(stagingDir)

	remote, err := c.remoteURL(ctx, u)
	if err != nil {
		return Checkout{}, err
	}
	cloneArgs := []string{"clone", "--depth=1"}
	if ref != "" && !looksLikeSHA(ref) {
		cloneArgs = append(cloneArgs, "--branch", ref)
	}
	cloneArgs = append(cloneArgs, remote, stagingDir)
	if _, err := c.runner.Run(ctx, repoDir, cloneArgs...); err != nil {
		return Checkout{}, fmt.Errorf("git clone: %w", err)
	}

	if err := os.Rename(stagingDir, finalDir); err != nil {
		return Checkout{}, fmt.Errorf("promote checkout: %w", err)
	}
	return Checkout{Path: finalDir, SHA: sha}, nil
}

// resolveSHA turns ref into a concrete commit SHA without (necessarily)
// cloning. If ref already looks like a SHA, it is returned as-is.
// Otherwise `git ls-remote` is used to ask the server for the ref's tip.
func (c *Cloner) resolveSHA(ctx context.Context, u URL, ref string) (string, error) {
	if looksLikeSHA(ref) {
		return ref, nil
	}
	remoteRef := "HEAD"
	if ref != "" {
		remoteRef = ref
	}
	remote, err := c.remoteURL(ctx, u)
	if err != nil {
		return "", err
	}
	out, err := c.runner.Run(ctx, c.root, "ls-remote", remote, remoteRef)
	if err != nil {
		return "", fmt.Errorf("git ls-remote: %w", err)
	}
	fields := strings.Fields(out)
	if len(fields) == 0 {
		return "", fmt.Errorf("git ls-remote returned no output for %q", remoteRef)
	}
	return fields[0], nil
}

func looksLikeSHA(s string) bool {
	if len(s) < 7 || len(s) > 40 {
		return false
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

// execRunner shells out to the system git binary.
type execRunner struct{}

func (execRunner) Run(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%w: %s", err, string(out))
	}
	return string(out), nil
}
