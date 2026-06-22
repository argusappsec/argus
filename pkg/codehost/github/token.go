package github

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// defaultAPIBase is GitHub's REST API root. Overridable for tests.
const defaultAPIBase = "https://api.github.com"

// tokenRefreshBuffer is how long before expiry a cached installation token is
// considered stale, so a token is never handed out moments before it dies.
const tokenRefreshBuffer = time.Minute

// TokenMinter mints short-lived installation access tokens for a GitHub App
// (App JWT → installation token, ADR 0008). It caches the token and refreshes
// it only when it is near expiry, so repeated clones/API calls reuse one
// token. Safe for concurrent use.
type TokenMinter struct {
	appID          string
	installationID string
	key            *rsa.PrivateKey

	httpClient *http.Client
	apiBase    string
	now        func() time.Time

	mu      sync.Mutex
	token   string
	expires time.Time
}

// MinterOption customizes a TokenMinter (test seams: HTTP transport, API
// base, clock).
type MinterOption func(*TokenMinter)

// WithHTTPClient sets the HTTP client used to call the GitHub API.
func WithHTTPClient(c *http.Client) MinterOption { return func(m *TokenMinter) { m.httpClient = c } }

// WithAPIBase overrides the API root (default https://api.github.com).
func WithAPIBase(base string) MinterOption {
	return func(m *TokenMinter) { m.apiBase = strings.TrimRight(base, "/") }
}

// WithClock overrides the clock used for JWT timestamps and cache expiry.
func WithClock(now func() time.Time) MinterOption { return func(m *TokenMinter) { m.now = now } }

// NewTokenMinter builds a minter for the App identified by appID +
// installationID, signing JWTs with the given RSA private key.
func NewTokenMinter(appID, installationID string, key *rsa.PrivateKey, opts ...MinterOption) *TokenMinter {
	m := &TokenMinter{
		appID:          appID,
		installationID: installationID,
		key:            key,
		httpClient:     http.DefaultClient,
		apiBase:        defaultAPIBase,
		now:            time.Now,
	}
	for _, o := range opts {
		o(m)
	}
	return m
}

// NewTokenMinterFromPEM parses a PEM-encoded RSA private key (the App's .pem)
// and returns a minter.
func NewTokenMinterFromPEM(appID, installationID string, pemBytes []byte, opts ...MinterOption) (*TokenMinter, error) {
	key, err := parseRSAPrivateKey(pemBytes)
	if err != nil {
		return nil, err
	}
	return NewTokenMinter(appID, installationID, key, opts...), nil
}

// Token returns a valid installation token, minting a fresh one only when the
// cached token is absent or within tokenRefreshBuffer of expiry.
func (m *TokenMinter) Token(ctx context.Context) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.token != "" && m.now().Add(tokenRefreshBuffer).Before(m.expires) {
		return m.token, nil
	}

	jwt, err := m.appJWT()
	if err != nil {
		return "", fmt.Errorf("github: app jwt: %w", err)
	}

	url := fmt.Sprintf("%s/app/installations/%s/access_tokens", m.apiBase, m.installationID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return "", fmt.Errorf("github: build token request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("github: mint installation token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github: mint installation token: status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var out struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("github: parse token response: %w", err)
	}
	if out.Token == "" {
		return "", fmt.Errorf("github: token response had no token")
	}

	m.token = out.Token
	m.expires = out.ExpiresAt
	return m.token, nil
}

// appJWT builds and signs the short-lived App JWT (RS256) used to mint an
// installation token. iat is backdated 60s to tolerate clock skew; exp is
// capped well under GitHub's 10-minute maximum.
func (m *TokenMinter) appJWT() (string, error) {
	now := m.now()
	header := map[string]any{"alg": "RS256", "typ": "JWT"}
	claims := map[string]any{
		"iat": now.Add(-60 * time.Second).Unix(),
		"exp": now.Add(9 * time.Minute).Unix(),
		"iss": m.appID,
	}

	hb, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := b64(hb) + "." + b64(cb)

	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, m.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// parseRSAPrivateKey accepts PKCS#1 ("RSA PRIVATE KEY") or PKCS#8 ("PRIVATE
// KEY") PEM, the two forms GitHub hands out.
func parseRSAPrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("github: no PEM block in private key")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("github: parse private key: %w", err)
	}
	key, ok := keyAny.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("github: private key is not RSA")
	}
	return key, nil
}

// LoadPrivateKeyFile reads and parses a PEM private key from disk.
func LoadPrivateKeyFile(path string) (*rsa.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("github: read private key: %w", err)
	}
	return parseRSAPrivateKey(b)
}
