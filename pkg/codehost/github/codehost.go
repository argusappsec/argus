package github

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/argusappsec/argus/pkg/codehost"
)

// CodeHost is the GitHub implementation of codehost.CodeHost (ADR 0010). It
// authenticates API calls and clones with an installation token minted on
// demand. The acting installation is derived per repository, never pinned
// (ADR 0015): a webhook event seeds it via NoteInstallation, and on-demand work
// resolves it through the App JWT. Tokens are minted per installation, so the
// same App acts on every organization it is installed on. It is the only
// implementation today.
type CodeHost struct {
	minter     *TokenMinter
	cloner     *Cloner
	cloneRun   Runner // git runner for clones; nil means the system git binary
	httpClient *http.Client
	apiBase    string

	mu       sync.Mutex
	installs map[string]string // repo full name → installation id
}

// NewCodeHost builds a GitHub CodeHost. cacheRoot is where clones are cached;
// the minter authenticates clones and API calls. Functional options mirror
// the minter's test seams (HTTP transport, API base, git runner).
func NewCodeHost(cacheRoot string, minter *TokenMinter, opts ...CodeHostOption) *CodeHost {
	h := &CodeHost{
		minter:     minter,
		httpClient: http.DefaultClient,
		apiBase:    defaultAPIBase,
		installs:   map[string]string{},
	}
	for _, o := range opts {
		o(h)
	}
	// The cloner carries no fixed auth: Clone binds it to the repo's resolved
	// installation per call, since one CodeHost spans many installations.
	if h.cloneRun != nil {
		h.cloner = NewClonerWithRunner(cacheRoot, h.cloneRun)
	} else {
		h.cloner = NewCloner(cacheRoot)
	}
	return h
}

// NoteInstallation records that repo belongs to installationID, as learned from
// a webhook event's payload. Subsequent calls for that repo skip the App-JWT
// lookup and mint the token for this installation directly (ADR 0015).
func (h *CodeHost) NoteInstallation(repo codehost.Repo, installationID string) {
	if installationID == "" {
		return
	}
	h.mu.Lock()
	h.installs[repo.FullName] = installationID
	h.mu.Unlock()
}

// resolveInstallation returns the id of the installation that owns repo. A
// value seeded from a webhook event (NoteInstallation) is used as-is;
// otherwise the App JWT resolves it via GET /repos/{owner}/{repo}/installation
// (on-demand reviews) and the result is cached. A repo the App is not installed
// on yields a clear error naming the repo.
func (h *CodeHost) resolveInstallation(ctx context.Context, repo codehost.Repo) (string, error) {
	h.mu.Lock()
	if id, ok := h.installs[repo.FullName]; ok {
		h.mu.Unlock()
		return id, nil
	}
	h.mu.Unlock()

	url := fmt.Sprintf("%s/repos/%s/%s/installation", h.apiBase, repo.Owner, repo.Name)
	resp, body, err := h.doAppJWT(ctx, http.MethodGet, url)
	if err != nil {
		return "", err
	}
	if resp.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("github: the App is not installed on %s", repo.FullName)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github: resolve installation for %s: status %d: %s", repo.FullName, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("github: parse installation for %s: %w", repo.FullName, err)
	}
	if out.ID == 0 {
		return "", fmt.Errorf("github: installation response for %s had no id", repo.FullName)
	}
	id := strconv.FormatInt(out.ID, 10)
	h.mu.Lock()
	h.installs[repo.FullName] = id
	h.mu.Unlock()
	return id, nil
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

// WithCloneRunner overrides the git runner used for clones so tests can drive
// the authenticated clone path without shelling out to git or hitting network.
func WithCloneRunner(r Runner) CodeHostOption {
	return func(h *CodeHost) { h.cloneRun = r }
}

// ParseURL implements codehost.CodeHost.
func (h *CodeHost) ParseURL(raw string) (codehost.Repo, error) {
	u, err := ParseURL(raw)
	if err != nil {
		return codehost.Repo{}, err
	}
	return codehost.Repo{Host: u.Host, Owner: u.Owner, Name: u.Name, FullName: u.FullName}, nil
}

// Clone implements codehost.CodeHost. It resolves the repo's installation and
// clones with a token minted for that installation, so a private repo on any
// installed organization succeeds.
func (h *CodeHost) Clone(ctx context.Context, repo codehost.Repo, ref string) (codehost.Checkout, error) {
	installID, err := h.resolveInstallation(ctx, repo)
	if err != nil {
		return codehost.Checkout{}, err
	}
	cloner := h.cloner.WithAuth(func(ctx context.Context) (string, error) {
		return h.minter.Token(ctx, installID)
	})
	co, err := cloner.Clone(ctx, URL{Host: repo.Host, Owner: repo.Owner, Name: repo.Name, FullName: repo.FullName}, ref)
	if err != nil {
		return codehost.Checkout{}, err
	}
	return codehost.Checkout{Path: co.Path, SHA: co.SHA}, nil
}

// PostComment implements codehost.CodeHost. A PR comment is an issue comment:
// POST /repos/{owner}/{repo}/issues/{number}/comments.
func (h *CodeHost) PostComment(ctx context.Context, repo codehost.Repo, number int, body string) error {
	installID, err := h.resolveInstallation(ctx, repo)
	if err != nil {
		return err
	}
	return h.postComment(ctx, installID, repo, number, body)
}

// postComment posts an issue comment using an already-resolved installation, so
// PostReview does not re-resolve for its summary comment.
func (h *CodeHost) postComment(ctx context.Context, installID string, repo codehost.Repo, number int, body string) error {
	url := fmt.Sprintf("%s/repos/%s/%s/issues/%d/comments", h.apiBase, repo.Owner, repo.Name, number)
	payload, err := json.Marshal(map[string]string{"body": body})
	if err != nil {
		return err
	}
	resp, respBody, err := h.doAuthed(ctx, installID, http.MethodPost, url, payload)
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
	installID, err := h.resolveInstallation(ctx, repo)
	if err != nil {
		return codehost.PRDiff{}, err
	}
	url := fmt.Sprintf("%s/repos/%s/%s/pulls/%d/files?per_page=100", h.apiBase, repo.Owner, repo.Name, number)
	var diff codehost.PRDiff
	for url != "" {
		resp, body, err := h.doAuthed(ctx, installID, http.MethodGet, url, nil)
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
	installID, err := h.resolveInstallation(ctx, repo)
	if err != nil {
		return err
	}
	if replace {
		if err := h.deletePriorReview(ctx, installID, repo, number); err != nil {
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
		resp, respBody, err := h.doAuthed(ctx, installID, http.MethodPost, url, payload)
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
			return fmt.Errorf("github: post inline comment: status %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
		}
	}
	return h.postComment(ctx, installID, repo, number, review.Summary+"\n"+reviewMarker)
}

// deletePriorReview removes the bot's previously posted summary issue comment
// and inline review comments (those carrying reviewMarker).
func (h *CodeHost) deletePriorReview(ctx context.Context, installID string, repo codehost.Repo, number int) error {
	inlineList := fmt.Sprintf("%s/repos/%s/%s/pulls/%d/comments?per_page=100", h.apiBase, repo.Owner, repo.Name, number)
	if err := h.deleteMarkedComments(ctx, installID, inlineList, "%s/repos/%s/%s/pulls/comments/%d", repo); err != nil {
		return err
	}
	issueList := fmt.Sprintf("%s/repos/%s/%s/issues/%d/comments?per_page=100", h.apiBase, repo.Owner, repo.Name, number)
	return h.deleteMarkedComments(ctx, installID, issueList, "%s/repos/%s/%s/issues/comments/%d", repo)
}

// deleteMarkedComments pages through listURL, and for every comment whose body
// carries reviewMarker issues a DELETE built from deleteFmt (apiBase, owner,
// name, id).
func (h *CodeHost) deleteMarkedComments(ctx context.Context, installID, listURL, deleteFmt string, repo codehost.Repo) error {
	for listURL != "" {
		resp, body, err := h.doAuthed(ctx, installID, http.MethodGet, listURL, nil)
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
			delResp, delBody, err := h.doAuthed(ctx, installID, http.MethodDelete, delURL, nil)
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
// repositories the installation that owns repo can access. The installation is
// derived from repo (ADR 0015), so gating consults the repos of the *event's*
// installation, never a pinned one. Pagination is followed so the full set is
// returned (gating must not silently truncate — ADR 0008).
func (h *CodeHost) InstallationRepos(ctx context.Context, repo codehost.Repo) ([]string, error) {
	installID, err := h.resolveInstallation(ctx, repo)
	if err != nil {
		return nil, err
	}
	url := fmt.Sprintf("%s/installation/repositories?per_page=100", h.apiBase)
	var names []string
	for url != "" {
		resp, body, err := h.doAuthed(ctx, installID, http.MethodGet, url, nil)
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

// doAuthed performs a request authenticated with the given installation's
// token (minting/reusing it) and returns the response (body already drained).
func (h *CodeHost) doAuthed(ctx context.Context, installID, method, url string, payload []byte) (*http.Response, []byte, error) {
	token, err := h.minter.Token(ctx, installID)
	if err != nil {
		return nil, nil, err
	}
	return h.do(ctx, "Bearer "+token, method, url, payload)
}

// doAppJWT performs a request authenticated with a freshly signed App JWT — the
// App-level credential used before an installation token exists (resolving a
// repo's installation). The body is drained and returned.
func (h *CodeHost) doAppJWT(ctx context.Context, method, url string) (*http.Response, []byte, error) {
	jwt, err := h.minter.AppJWT()
	if err != nil {
		return nil, nil, fmt.Errorf("github: app jwt: %w", err)
	}
	return h.do(ctx, "Bearer "+jwt, method, url, nil)
}

// do issues one HTTP request with the given Authorization header and returns
// the response with its body already read.
func (h *CodeHost) do(ctx context.Context, authorization, method, url string, payload []byte) (*http.Response, []byte, error) {
	var rdr io.Reader
	if payload != nil {
		rdr = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rdr)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Authorization", authorization)
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
