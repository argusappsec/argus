// Package github is the GitHub App channel (ADR 0008): an HTTP listener that
// receives signed webhook deliveries, verifies them, and drives Argus on a
// Pull Request. This file is the webhook-ingest deep module — a pure unit
// (no I/O) that verifies the HMAC signature and parses a delivery into a
// typed Event. Invalid signature, unhandled event type, and comment events
// are distinct outcomes the channel acts on.
package github

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// EventKind classifies a parsed delivery.
type EventKind int

const (
	// KindIgnore is an event Argus does not act on (unhandled type).
	KindIgnore EventKind = iota
	// KindPullRequest is a pull_request event (opened/synchronize/…).
	KindPullRequest
	// KindComment is an issue_comment or pull_request_review_comment. The
	// channel decides whether it carries the @argus mention (ADR 0008).
	KindComment
)

// Event is the typed result of parsing a verified delivery.
type Event struct {
	Kind   EventKind
	Action string // "opened", "synchronize", "created", …

	Repo   string // canonical "github.com/<owner>/<name>"
	Owner  string
	Name   string
	Number int // PR (or issue) number

	BaseSHA string
	HeadSHA string

	// Author is the PR author login (pull_request events).
	Author string
	// Commenter is the comment author login (comment events).
	Commenter string
	// Body is the comment body (comment events).
	Body string
}

// ErrInvalidSignature is returned when the HMAC does not verify — a forged or
// unsigned delivery. The channel rejects it; this is distinct from an event
// that verifies but is simply not acted on (KindIgnore).
var ErrInvalidSignature = errors.New("github: invalid webhook signature")

// Parse verifies the delivery's HMAC against secret and parses it into a typed
// Event. eventType is the X-GitHub-Event header; sigHeader is the
// X-Hub-Signature-256 header (form "sha256=<hex>"). A signature that does not
// verify (including an absent one) returns ErrInvalidSignature.
func Parse(eventType string, body []byte, sigHeader, secret string) (Event, error) {
	if !verifySignature(body, sigHeader, secret) {
		return Event{}, ErrInvalidSignature
	}

	switch eventType {
	case "pull_request":
		return parsePullRequest(body)
	case "issue_comment":
		return parseIssueComment(body)
	case "pull_request_review_comment":
		return parseReviewComment(body)
	default:
		return Event{Kind: KindIgnore, Action: eventType}, nil
	}
}

// verifySignature constant-time compares HMAC-SHA256(secret, body) to the
// hex digest in sigHeader.
func verifySignature(body []byte, sigHeader, secret string) bool {
	const prefix = "sha256="
	if !strings.HasPrefix(sigHeader, prefix) {
		return false
	}
	want, err := hex.DecodeString(strings.TrimPrefix(sigHeader, prefix))
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hmac.Equal(want, mac.Sum(nil))
}

func parsePullRequest(body []byte) (Event, error) {
	var p struct {
		Action      string `json:"action"`
		Number      int    `json:"number"`
		PullRequest struct {
			User struct {
				Login string `json:"login"`
			} `json:"user"`
			Head struct {
				SHA string `json:"sha"`
			} `json:"head"`
			Base struct {
				SHA string `json:"sha"`
			} `json:"base"`
		} `json:"pull_request"`
		Repository repository `json:"repository"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return Event{}, fmt.Errorf("github: parse pull_request: %w", err)
	}
	owner, name, full := p.Repository.canonical()
	return Event{
		Kind:    KindPullRequest,
		Action:  p.Action,
		Repo:    full,
		Owner:   owner,
		Name:    name,
		Number:  p.Number,
		BaseSHA: p.PullRequest.Base.SHA,
		HeadSHA: p.PullRequest.Head.SHA,
		Author:  p.PullRequest.User.Login,
	}, nil
}

func parseIssueComment(body []byte) (Event, error) {
	var p struct {
		Action string `json:"action"`
		Issue  struct {
			Number int `json:"number"`
		} `json:"issue"`
		Comment struct {
			Body string `json:"body"`
			User struct {
				Login string `json:"login"`
			} `json:"user"`
		} `json:"comment"`
		Repository repository `json:"repository"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return Event{}, fmt.Errorf("github: parse issue_comment: %w", err)
	}
	owner, name, full := p.Repository.canonical()
	return Event{
		Kind:      KindComment,
		Action:    p.Action,
		Repo:      full,
		Owner:     owner,
		Name:      name,
		Number:    p.Issue.Number,
		Commenter: p.Comment.User.Login,
		Body:      p.Comment.Body,
	}, nil
}

func parseReviewComment(body []byte) (Event, error) {
	var p struct {
		Action      string `json:"action"`
		PullRequest struct {
			Number int `json:"number"`
		} `json:"pull_request"`
		Comment struct {
			Body string `json:"body"`
			User struct {
				Login string `json:"login"`
			} `json:"user"`
		} `json:"comment"`
		Repository repository `json:"repository"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return Event{}, fmt.Errorf("github: parse review_comment: %w", err)
	}
	owner, name, full := p.Repository.canonical()
	return Event{
		Kind:      KindComment,
		Action:    p.Action,
		Repo:      full,
		Owner:     owner,
		Name:      name,
		Number:    p.PullRequest.Number,
		Commenter: p.Comment.User.Login,
		Body:      p.Comment.Body,
	}, nil
}

// repository mirrors the webhook's repository object.
type repository struct {
	FullName string `json:"full_name"` // "owner/name"
	Name     string `json:"name"`
	Owner    struct {
		Login string `json:"login"`
	} `json:"owner"`
}

// canonical returns (owner, name, "github.com/owner/name").
func (r repository) canonical() (owner, name, full string) {
	owner = r.Owner.Login
	name = r.Name
	if r.FullName != "" {
		if i := strings.IndexByte(r.FullName, '/'); i > 0 {
			owner = r.FullName[:i]
			name = r.FullName[i+1:]
		}
	}
	return owner, name, "github.com/" + owner + "/" + name
}
