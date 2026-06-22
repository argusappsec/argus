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

// reviewMarker is an invisible HTML marker embedded in every comment
// argus[bot] posts through PostReview. On a synchronize replace it lets us find
// and remove the bot's prior summary and inline comments without depending on
// the bot login being known.
const reviewMarker = "<!-- argus-review -->"

// FetchPRDiff implements codehost.CodeHost: GET /repos/{o}/{r}/pulls/{n}/files,
// following pagination so no changed file is silently dropped. The GitHub patch
// string is parsed into head-side hunks for inline placement.
func (h *CodeHost) FetchPRDiff(ctx context.Context, repo codehost.Repo, number int) (codehost.PRDiff, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/pulls/%d/files?per_page=100", h.apiBase, repo.Owner, repo.Name, number)
	var diff codehost.PRDiff
	for url != "" {
		resp, body, err := h.doAuthed(ctx, http.MethodGet, url, nil)
		if err != nil {
			return codehost.PRDiff{}, err
		}
		if resp.StatusCode != http.StatusOK {
			return codehost.PRDiff{}, fmt.Errorf("github: fetch PR diff: status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
		}
		var files []struct {
			Filename string `json:"filename"`
			Status   string `json:"status"`
			Patch    string `json:"patch"`
		}
		if err := json.Unmarshal(body, &files); err != nil {
			return codehost.PRDiff{}, fmt.Errorf("github: parse PR files: %w", err)
		}
		for _, f := range files {
			diff.Files = append(diff.Files, codehost.ChangedFile{
				Path:   f.Filename,
				Status: f.Status,
				Patch:  f.Patch,
				Hunks:  parseHunks(f.Patch),
			})
		}
		url = nextPageURL(resp.Header.Get("Link"))
	}
	return diff, nil
}

// PostReview implements codehost.CodeHost. The summary is an issue comment and
// each on-diff finding is an individual PR review comment; both carry
// reviewMarker. On replace (synchronize) the bot's prior marked comments are
// deleted first, so a new push refreshes the review in place. Both surfaces are
// independently deletable — unlike a submitted GitHub review object, which
// cannot be removed — so nothing stacks across pushes.
func (h *CodeHost) PostReview(ctx context.Context, repo codehost.Repo, number int, review codehost.Review, replace bool) error {
	if replace {
		if err := h.deletePriorReview(ctx, repo, number); err != nil {
			return err
		}
	}
	for _, c := range review.Inline {
		url := fmt.Sprintf("%s/repos/%s/%s/pulls/%d/comments", h.apiBase, repo.Owner, repo.Name, number)
		payload, err := json.Marshal(map[string]any{
			"body":      c.Body + "\n" + reviewMarker,
			"commit_id": review.HeadSHA,
			"path":      c.Path,
			"line":      c.Line,
			"side":      "RIGHT",
		})
		if err != nil {
			return err
		}
		resp, respBody, err := h.doAuthed(ctx, http.MethodPost, url, payload)
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
			return fmt.Errorf("github: post inline comment: status %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
		}
	}
	return h.PostComment(ctx, repo, number, review.Summary+"\n"+reviewMarker)
}

// deletePriorReview removes the bot's previously posted summary issue comment
// and inline review comments (those carrying reviewMarker).
func (h *CodeHost) deletePriorReview(ctx context.Context, repo codehost.Repo, number int) error {
	inlineList := fmt.Sprintf("%s/repos/%s/%s/pulls/%d/comments?per_page=100", h.apiBase, repo.Owner, repo.Name, number)
	if err := h.deleteMarkedComments(ctx, inlineList, "%s/repos/%s/%s/pulls/comments/%d", repo); err != nil {
		return err
	}
	issueList := fmt.Sprintf("%s/repos/%s/%s/issues/%d/comments?per_page=100", h.apiBase, repo.Owner, repo.Name, number)
	return h.deleteMarkedComments(ctx, issueList, "%s/repos/%s/%s/issues/comments/%d", repo)
}

// deleteMarkedComments pages through listURL, and for every comment whose body
// carries reviewMarker issues a DELETE built from deleteFmt (apiBase, owner,
// name, id).
func (h *CodeHost) deleteMarkedComments(ctx context.Context, listURL, deleteFmt string, repo codehost.Repo) error {
	for listURL != "" {
		resp, body, err := h.doAuthed(ctx, http.MethodGet, listURL, nil)
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("github: list prior comments: status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
		}
		var comments []struct {
			ID   int64  `json:"id"`
			Body string `json:"body"`
		}
		if err := json.Unmarshal(body, &comments); err != nil {
			return fmt.Errorf("github: parse prior comments: %w", err)
		}
		for _, c := range comments {
			if !strings.Contains(c.Body, reviewMarker) {
				continue
			}
			delURL := fmt.Sprintf(deleteFmt, h.apiBase, repo.Owner, repo.Name, c.ID)
			delResp, delBody, err := h.doAuthed(ctx, http.MethodDelete, delURL, nil)
			if err != nil {
				return err
			}
			if delResp.StatusCode != http.StatusNoContent && delResp.StatusCode != http.StatusOK {
				return fmt.Errorf("github: delete prior comment: status %d: %s", delResp.StatusCode, strings.TrimSpace(string(delBody)))
			}
		}
		listURL = nextPageURL(resp.Header.Get("Link"))
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
