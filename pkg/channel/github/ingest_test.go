package github

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
)

const testSecret = "s3cr3t-webhook-key"

func sign(body []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

const openedPR = `{
  "action": "opened",
  "number": 42,
  "pull_request": {
    "user": {"login": "alice"},
    "head": {"sha": "headsha111"},
    "base": {"sha": "basesha000"}
  },
  "repository": {"full_name": "argusappsec/argus", "name": "argus", "owner": {"login": "argusappsec"}}
}`

const issueComment = `{
  "action": "created",
  "issue": {"number": 7},
  "comment": {"body": "@argus explain this", "user": {"login": "bob"}},
  "repository": {"full_name": "argusappsec/argus", "name": "argus", "owner": {"login": "argusappsec"}}
}`

func TestParse_ValidPullRequest(t *testing.T) {
	body := []byte(openedPR)
	evt, err := Parse("pull_request", body, sign(body, testSecret), testSecret)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if evt.Kind != KindPullRequest {
		t.Errorf("kind = %v, want pull_request", evt.Kind)
	}
	if evt.Action != "opened" || evt.Number != 42 {
		t.Errorf("action/number = %q/%d", evt.Action, evt.Number)
	}
	if evt.Repo != "github.com/argusappsec/argus" {
		t.Errorf("repo = %q", evt.Repo)
	}
	if evt.Owner != "argusappsec" || evt.Name != "argus" {
		t.Errorf("owner/name = %q/%q", evt.Owner, evt.Name)
	}
	if evt.HeadSHA != "headsha111" || evt.BaseSHA != "basesha000" {
		t.Errorf("head/base = %q/%q", evt.HeadSHA, evt.BaseSHA)
	}
	if evt.Author != "alice" {
		t.Errorf("author = %q, want the PR author for metadata", evt.Author)
	}
}

func TestParse_TamperedBodyRejected(t *testing.T) {
	body := []byte(openedPR)
	sig := sign(body, testSecret)
	// Signature was computed over the original body; a mutated body must fail.
	_, err := Parse("pull_request", []byte(openedPR+" "), sig, testSecret)
	if !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("err = %v, want ErrInvalidSignature", err)
	}
}

func TestParse_WrongSecretRejected(t *testing.T) {
	body := []byte(openedPR)
	_, err := Parse("pull_request", body, sign(body, "other-secret"), testSecret)
	if !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("err = %v, want ErrInvalidSignature", err)
	}
}

func TestParse_MissingSignatureRejected(t *testing.T) {
	body := []byte(openedPR)
	for _, sig := range []string{"", "not-a-sig", "sha256=zzzz"} {
		if _, err := Parse("pull_request", body, sig, testSecret); !errors.Is(err, ErrInvalidSignature) {
			t.Errorf("sig %q: err = %v, want ErrInvalidSignature", sig, err)
		}
	}
}

func TestParse_UnhandledEventIgnored(t *testing.T) {
	body := []byte(`{"zen": "Keep it logically awesome."}`)
	evt, err := Parse("ping", body, sign(body, testSecret), testSecret)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if evt.Kind != KindIgnore {
		t.Errorf("kind = %v, want ignore for unhandled event type", evt.Kind)
	}
}

func TestParse_CommentSurfacesLoginBodyRepoNumber(t *testing.T) {
	body := []byte(issueComment)
	evt, err := Parse("issue_comment", body, sign(body, testSecret), testSecret)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if evt.Kind != KindComment {
		t.Errorf("kind = %v, want comment", evt.Kind)
	}
	if evt.Commenter != "bob" {
		t.Errorf("commenter = %q", evt.Commenter)
	}
	if evt.Body != "@argus explain this" {
		t.Errorf("body = %q", evt.Body)
	}
	if evt.Number != 7 || evt.Repo != "github.com/argusappsec/argus" {
		t.Errorf("number/repo = %d/%q", evt.Number, evt.Repo)
	}
}
