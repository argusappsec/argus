package github_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/argusappsec/argus/pkg/codehost/github"
)

func testKeyPEM(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

// tokenServer returns installation tokens with a controllable expiry and
// counts how many times it was called.
func tokenServer(t *testing.T, expiries []time.Time) (*httptest.Server, *int32) {
	t.Helper()
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if r.Header.Get("Authorization") == "" {
			t.Errorf("expected App JWT Authorization header")
		}
		exp := expiries[len(expiries)-1]
		if int(n) <= len(expiries) {
			exp = expiries[n-1]
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":      fmt.Sprintf("ghs_token_%d", n),
			"expires_at": exp.Format(time.RFC3339),
		})
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func TestTokenMinter_MintsReusesAndRefreshes(t *testing.T) {
	base := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	srv, calls := tokenServer(t, []time.Time{base.Add(time.Hour), base.Add(3 * time.Hour)})

	now := base
	minter, err := github.NewTokenMinterFromPEM("123", "456", testKeyPEM(t),
		github.WithAPIBase(srv.URL),
		github.WithHTTPClient(srv.Client()),
		github.WithClock(func() time.Time { return now }),
	)
	if err != nil {
		t.Fatalf("minter: %v", err)
	}

	// First call mints.
	tok, err := minter.Token(context.Background())
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if tok != "ghs_token_1" {
		t.Errorf("token = %q", tok)
	}
	if got := atomic.LoadInt32(calls); got != 1 {
		t.Fatalf("calls = %d, want 1", got)
	}

	// Well within validity → reuse, no new HTTP call.
	now = base.Add(10 * time.Minute)
	if tok, _ := minter.Token(context.Background()); tok != "ghs_token_1" {
		t.Errorf("reuse token = %q", tok)
	}
	if got := atomic.LoadInt32(calls); got != 1 {
		t.Errorf("calls after reuse = %d, want 1", got)
	}

	// Past expiry (minus buffer) → refresh, new token.
	now = base.Add(90 * time.Minute)
	tok2, err := minter.Token(context.Background())
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if tok2 != "ghs_token_2" {
		t.Errorf("refreshed token = %q", tok2)
	}
	if got := atomic.LoadInt32(calls); got != 2 {
		t.Errorf("calls after refresh = %d, want 2", got)
	}
}
