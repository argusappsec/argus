package github

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/redcarbon-dev/argus/pkg/codehost"
)

// CodeHost is the GitHub implementation of codehost.CodeHost (ADR 0010). It
// authenticates API calls and clones with an installation token minted on
// demand. It is the only implementation today.
type CodeHost struct {
	minter     *TokenMinter
	cloner     *Cloner
	httpClient *http.Client
	apiBase    string
}

// NewCodeHost builds a GitHub CodeHost. cacheRoot is where clones are cached;
// the minter authenticates clones and API calls. Functional options mirror
// the minter's test seams (HTTP transport, API base).
func NewCodeHost(cacheRoot string, minter *TokenMinter, opts ...CodeHostOption) *CodeHost {
	h := &CodeHost{
		minter:     minter,
		httpClient: http.DefaultClient,
		apiBase:    defaultAPIBase,
	}
	for _, o := range opts {
		o(h)
	}
	h.cloner = NewCloner(cacheRoot).WithAuth(minter.Token)
	return h
}

// CodeHostOption customizes a CodeHost (test seams).
type CodeHostOption func(*CodeHost)

// WithCodeHostHTTPClient sets the HTTP client used for API calls.
func WithCodeHostHTTPClient(c *http.Client) CodeHostOption {
	return func(h *CodeHost) { h.httpClient = c }
}

// WithCodeHostAPIBase overrides the API root.
func WithCodeHostAPIBase(base string) CodeHostOption {
	return func(h *CodeHost) { h.apiBase = strings.TrimRight(base, "/") }
}

// ParseURL implements codehost.CodeHost.
func (h *CodeHost) ParseURL(raw string) (codehost.Repo, error) {
	u, err := ParseURL(raw)
	if err != nil {
		return codehost.Repo{}, err
	}
	return codehost.Repo{Host: u.Host, Owner: u.Owner, Name: u.Name, FullName: u.FullName}, nil
}

// Clone implements codehost.CodeHost using the authenticated cloner.
func (h *CodeHost) Clone(ctx context.Context, repo codehost.Repo, ref string) (codehost.Checkout, error) {
	co, err := h.cloner.Clone(ctx, URL{Host: repo.Host, Owner: repo.Owner, Name: repo.Name, FullName: repo.FullName}, ref)
	if err != nil {
		return codehost.Checkout{}, err
	}
	return codehost.Checkout{Path: co.Path, SHA: co.SHA}, nil
}

// PostComment implements codehost.CodeHost. A PR comment is an issue comment:
// POST /repos/{owner}/{repo}/issues/{number}/comments.
func (h *CodeHost) PostComment(ctx context.Context, repo codehost.Repo, number int, body string) error {
	url := fmt.Sprintf("%s/repos/%s/%s/issues/%d/comments", h.apiBase, repo.Owner, repo.Name, number)
	payload, err := json.Marshal(map[string]string{"body": body})
	if err != nil {
		return err
	}
	resp, respBody, err := h.doAuthed(ctx, http.MethodPost, url, payload)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("github: post comment: status %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	return nil
}

// InstallationRepos implements codehost.CodeHost: the canonical names of the
// repositories the installation can access. Pagination is followed so the
// full set is returned (gating must not silently truncate — ADR 0008).
func (h *CodeHost) InstallationRepos(ctx context.Context) ([]string, error) {
	url := fmt.Sprintf("%s/installation/repositories?per_page=100", h.apiBase)
	var names []string
	for url != "" {
		resp, body, err := h.doAuthed(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("github: list installation repos: status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
		}
		var out struct {
			Repositories []struct {
				FullName string `json:"full_name"` // "owner/name"
			} `json:"repositories"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			return nil, fmt.Errorf("github: parse installation repos: %w", err)
		}
		for _, r := range out.Repositories {
			names = append(names, "github.com/"+r.FullName)
		}
		url = nextPageURL(resp.Header.Get("Link"))
	}
	return names, nil
}

// doAuthed performs an authenticated request, minting/reusing an installation
// token and returning the response (body already drained).
func (h *CodeHost) doAuthed(ctx context.Context, method, url string, payload []byte) (*http.Response, []byte, error) {
	token, err := h.minter.Token(ctx)
	if err != nil {
		return nil, nil, err
	}
	var rdr io.Reader
	if payload != nil {
		rdr = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rdr)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("github: %s %s: %w", method, url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp, body, nil
}

// nextPageURL extracts the rel="next" URL from a GitHub Link header, or "" if
// there is no next page.
func nextPageURL(link string) string {
	for part := range strings.SplitSeq(link, ",") {
		segs := strings.Split(strings.TrimSpace(part), ";")
		if len(segs) < 2 {
			continue
		}
		url := strings.Trim(strings.TrimSpace(segs[0]), "<>")
		for _, s := range segs[1:] {
			if strings.TrimSpace(s) == `rel="next"` {
				return url
			}
		}
	}
	return ""
}

// compile-time check that CodeHost satisfies the interface.
var _ codehost.CodeHost = (*CodeHost)(nil)
