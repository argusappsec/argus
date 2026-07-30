// Package openaicompat implements provider.Provider against the
// OpenAI-compatible chat-completions wire protocol.
//
// The package is named for the protocol, not for a vendor: the same wire
// format is spoken by OpenAI, by hosted aggregators and inference services
// (OpenRouter, Groq, Together, DeepSeek, Mistral, Cerebras), and by local
// runtimes (Ollama, vLLM, LM Studio, llama.cpp). Argus implements the
// protocol; it certifies nobody's server.
//
// That is why this is a hand-written net/http + encoding/json client rather
// than an SDK. Argus talks to servers that are *approximately* OpenAI, and a
// strictly typed client written for the real OpenAI rejects responses those
// servers legitimately return — absent usage, non-standard finish reasons,
// tool-call ids formed their own way. Tolerance is the feature here, not a
// compromise, so the decoder is deliberately lenient about everything it does
// not strictly need. There is no retry logic: the Gemini provider has none,
// and this matches that bar rather than regressing from it.
package openaicompat

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/argusappsec/argus/pkg/provider"
)

// DefaultBaseURL is the OpenAI public endpoint, used when Config.BaseURL is
// empty. Note the mandatory /v1 suffix: this protocol's sharpest footgun is
// that the API is not served at the domain root.
const DefaultBaseURL = "https://api.openai.com/v1"

// Config is the connection info for one compatible endpoint.
type Config struct {
	// APIKey may be empty: local runtimes need no key, and an empty key means
	// no Authorization header is sent at all.
	APIKey string
	// BaseURL is the API root including any path prefix (e.g.
	// "http://localhost:11434/v1"). Empty means DefaultBaseURL.
	BaseURL string
	// Model is the model id to generate with, as the endpoint names it.
	Model string
	// MaxOutputTokens caps the response length. Zero means the field is
	// omitted from the request entirely, which is both the ecosystem norm and
	// what the Gemini provider does.
	MaxOutputTokens int
	// HTTPClient is optional; nil yields a sane default. It exists so tests
	// can point the client at a stand-in server.
	HTTPClient *http.Client
}

// Client is an OpenAI-compatible chat-completions client. It satisfies
// provider.Provider.
type Client struct {
	apiKey          string
	baseURL         string // normalized: no trailing slash
	model           string
	maxOutputTokens int
	httpClient      *http.Client
}

// Client must remain usable wherever Argus expects an LLM provider.
var _ provider.Provider = (*Client)(nil)

// New validates cfg and returns a client bound to one endpoint and model.
func New(cfg Config) (*Client, error) {
	model := strings.TrimSpace(cfg.Model)
	if model == "" {
		return nil, fmt.Errorf("openaicompat: model is required")
	}

	base := strings.TrimSpace(cfg.BaseURL)
	if base == "" {
		base = DefaultBaseURL
	}
	// Normalized once here so the stored value is what appears in error
	// messages; the join itself (see do) is what guarantees a base URL carrying
	// a path keeps it.
	base = strings.TrimRight(base, "/")
	u, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("openaicompat: invalid base URL %q: %w", cfg.BaseURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("openaicompat: base URL %q must start with http:// or https://", cfg.BaseURL)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("openaicompat: base URL %q has no host", cfg.BaseURL)
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		// No overall timeout on purpose. The default transport already bounds
		// connection setup, so a dead endpoint still fails fast, while a long
		// Report on a slow local runtime is allowed to take the minutes it
		// legitimately needs. The caller's context is the deadline — the same
		// bar the Gemini provider sets.
		httpClient = &http.Client{}
	}

	return &Client{
		apiKey:          strings.TrimSpace(cfg.APIKey),
		baseURL:         base,
		model:           model,
		maxOutputTokens: cfg.MaxOutputTokens,
		httpClient:      httpClient,
	}, nil
}

// Generate performs one POST {base}/chat/completions turn.
func (c *Client) Generate(ctx context.Context, req provider.Request) (provider.Response, error) {
	body := chatRequest{
		Model:    c.model,
		Messages: toWireMessages(req.System, req.Messages),
		Tools:    toWireTools(req.Tools),
	}
	if c.maxOutputTokens > 0 {
		body.MaxTokens = &c.maxOutputTokens
	}

	raw, err := c.do(ctx, http.MethodPost, "/chat/completions", body)
	if err != nil {
		return provider.Response{}, c.translateFailure(err, len(req.Tools) > 0)
	}

	var decoded chatResponse
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return provider.Response{}, fmt.Errorf("openaicompat: decode response: %w", err)
	}
	return decoded.toResponse()
}

// ListModels performs GET {base}/models and returns the model ids the endpoint
// reports.
//
// It is the cheapest question worth asking of a compatible endpoint: one request
// establishes that the endpoint is reachable, that the key (if any) is accepted,
// and that a configured model id actually exists there — all before a single
// token is spent.
func (c *Client) ListModels(ctx context.Context) ([]string, error) {
	raw, err := c.do(ctx, http.MethodGet, "/models", nil)
	if err != nil {
		return nil, err
	}

	var decoded struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil, fmt.Errorf("openaicompat: decode model list: %w", err)
	}

	models := make([]string, 0, len(decoded.Data))
	for _, m := range decoded.Data {
		// An entry with no id names nothing and cannot be matched against a
		// configured model, so it is dropped rather than reported as "".
		if m.ID == "" {
			continue
		}
		models = append(models, m.ID)
	}
	return models, nil
}

// ErrToolCallingUnsupported reports that the endpoint refused a request
// carrying tool declarations. Argus is an agent loop built on tool calls: a
// model that cannot call them cannot read a file, run a scanner, or finalize a
// Report, so this is total inertia rather than degradation. Callers test for it
// with errors.Is, which is what lets a capability probe report it as a
// configuration verdict rather than as a failure.
var ErrToolCallingUnsupported = errors.New(
	"the endpoint rejected the request's tool declarations: this model does not support tool calling, which Argus needs for every Review")

// translateFailure turns a transport or status failure into the most accurate
// thing that can be said about it.
//
// A refusal of the tool declarations is the one case worth rewriting: the raw
// reply comes from a server the user did not write, and the plain-language
// verdict is what turns "Argus is broken" into "this model does not meet
// Argus's requirements". The verdict leads, and the server's own words follow it
// — dropping them would leave a user unable to check the diagnosis, and a
// diagnosis about a model's capabilities is exactly the kind worth checking.
func (c *Client) translateFailure(err error, requestCarriedToolDecls bool) error {
	var status *statusError
	if requestCarriedToolDecls && errors.As(err, &status) && status.looksLikeToolRejection() {
		return fmt.Errorf("openaicompat: model %q at %s: %w (the endpoint said: %s)",
			c.model, c.baseURL, ErrToolCallingUnsupported, status.detail)
	}
	return err
}

// do sends body (nil for a GET) to path under the base URL and returns the raw
// response bytes, translating non-2xx statuses into errors.
func (c *Client) do(ctx context.Context, method, path string, body any) ([]byte, error) {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("openaicompat: encode request: %w", err)
		}
		reader = bytes.NewReader(encoded)
	}

	// JoinPath rather than concatenation: it keeps any path the base URL
	// carries, collapses doubled slashes, and leaves a query string (which some
	// hosted endpoints require) attached to the end where it belongs.
	endpoint, err := url.JoinPath(c.baseURL, path)
	if err != nil {
		return nil, fmt.Errorf("openaicompat: build %s URL: %w", path, err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return nil, fmt.Errorf("openaicompat: build request: %w", err)
	}
	httpReq.Header.Set("Accept", "application/json")
	if body != nil {
		httpReq.Header.Set("Content-Type", "application/json")
	}
	// An empty key is not sent as an empty bearer token: local runtimes need
	// no key, and a malformed header is worse than an absent one.
	if c.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("openaicompat: %s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("openaicompat: read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, &statusError{
			method: method,
			path:   path,
			status: resp.StatusCode,
			detail: serverDetail(raw),
		}
	}
	return raw, nil
}

// statusError is a non-2xx reply. It quotes the server's own words, because the
// server on the other end is one Argus does not control and its complaint is
// usually the only actionable thing available.
type statusError struct {
	method string
	path   string
	status int
	detail string
}

func (e *statusError) Error() string {
	return fmt.Sprintf("openaicompat: %s %s: status %d: %s", e.method, e.path, e.status, e.detail)
}

// looksLikeToolRejection reports whether a client error actually means "I will
// not accept tool declarations".
//
// Both halves of the test matter, because Argus declares its tools on every
// turn of every Review: status alone would convict the model of a capability it
// may well have. A 400 is just as likely to mean the context window overflowed
// or that some other parameter was refused — each a different problem with a
// different fix — and answering any of those with "your model cannot call
// tools" points the user at the wrong one, which is precisely the failure this
// Provider exists to end. So the status must be one a refusal plausibly uses
// (the excluded ones each have an unambiguous meaning of their own: a bad key,
// a wrong URL or model id, a rate limit), and the server must have said
// something about tools or functions.
func (e *statusError) looksLikeToolRejection() bool {
	switch e.status {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound,
		http.StatusRequestTimeout, http.StatusTooManyRequests:
		return false
	}
	if e.status < 400 || e.status >= 500 {
		return false
	}
	lowered := strings.ToLower(e.detail)
	return strings.Contains(lowered, "tool") || strings.Contains(lowered, "function")
}

// bodyExcerptLimit caps how much of a server's error body is quoted back. Enough
// to be actionable; short enough that an HTML error page does not flood the log.
const bodyExcerptLimit = 512

// serverDetail extracts the most useful text from an error body: the standard
// error.message when the server sends one, otherwise a bounded excerpt of
// whatever it did send.
func serverDetail(raw []byte) string {
	var envelope struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &envelope); err == nil && envelope.Error.Message != "" {
		return truncate(envelope.Error.Message)
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return "(empty response body)"
	}
	return truncate(trimmed)
}

// truncate bounds an excerpt, dropping the partial rune a byte-wise cut can
// leave behind so the message stays printable.
func truncate(s string) string {
	if len(s) <= bodyExcerptLimit {
		return s
	}
	return strings.ToValidUTF8(s[:bodyExcerptLimit], "") + "…"
}
