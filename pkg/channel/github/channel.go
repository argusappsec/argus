package github

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"strings"
	"time"

	"github.com/redcarbon-dev/argus/pkg/audit"
	"github.com/redcarbon-dev/argus/pkg/auth"
	"github.com/redcarbon-dev/argus/pkg/codehost"
	"github.com/redcarbon-dev/argus/pkg/daemon"
	"github.com/redcarbon-dev/argus/pkg/report"
)

// maxBodyBytes bounds the webhook payload we read into memory.
const maxBodyBytes = 8 << 20 // 8 MiB

// Options carries the channel's resolved configuration.
type Options struct {
	Addr          string   // HTTP listen address
	WebhookSecret string   // resolved App webhook secret (raw)
	AutoEnroll    bool     // effective github.auto_enroll
	EnabledRepos  []string // explicit allow-list when AutoEnroll is false
}

// Server is the GitHub App channel (ADR 0008): an HTTP listener for webhook
// deliveries. Slice 1 spine — it verifies, attributes, gates, and posts an
// acknowledgment as argus[bot]; scanning arrives in later slices.
type Server struct {
	dc   *daemon.Context
	host codehost.CodeHost
	opts Options

	secretSHA string
	dedup     *deliveryCache
}

// NewServer builds the channel. host is the authenticated CodeHost the ack is
// posted through; opts carries the resolved secret and gating policy.
func NewServer(dc *daemon.Context, host codehost.CodeHost, opts Options) *Server {
	sum := sha256.Sum256([]byte(opts.WebhookSecret))
	return &Server{
		dc:        dc,
		host:      host,
		opts:      opts,
		secretSHA: hex.EncodeToString(sum[:]),
		dedup:     newDeliveryCache(2048),
	}
}

// Name implements daemon.Channel.
func (s *Server) Name() string { return "github" }

// Start listens for webhook deliveries until ctx is cancelled.
func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/webhook", s.handle)
	srv := &http.Server{Addr: s.opts.Addr, Handler: mux}

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("github: listen %s: %w", s.opts.Addr, err)
	}
	return nil
}

// handle is the webhook entrypoint: verify → de-dup → dispatch.
func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}

	eventType := r.Header.Get("X-GitHub-Event")
	sig := r.Header.Get("X-Hub-Signature-256")
	delivery := r.Header.Get("X-GitHub-Delivery")

	evt, err := Parse(eventType, body, sig, s.opts.WebhookSecret)
	if err != nil {
		// Forged or unsigned: reject. No operational detail leaks.
		http.Error(w, "signature verification failed", http.StatusUnauthorized)
		return
	}

	// De-dup by delivery id: a redelivery of an already-handled event is a
	// no-op. The id is reserved before work and only kept on success, so a
	// failed delivery can still be retried by GitHub.
	if delivery != "" && !s.dedup.reserve(delivery) {
		w.WriteHeader(http.StatusOK)
		return
	}

	if handleErr := s.dispatch(r.Context(), evt); handleErr != nil {
		if delivery != "" {
			s.dedup.release(delivery)
		}
		http.Error(w, "processing failed", http.StatusInternalServerError)
		return
	}
	if delivery != "" {
		s.dedup.commit(delivery)
	}
	w.WriteHeader(http.StatusOK)
}

// dispatch routes a verified event. Slice 2 runs an automatic review on an
// opened PR; other kinds (synchronize, comments) are accepted but not yet
// acted on — diff-aware synchronize and conversational comments arrive in
// later slices.
func (s *Server) dispatch(ctx context.Context, evt Event) error {
	if evt.Kind != KindPullRequest || evt.Action != "opened" {
		return nil
	}

	// Attribute the trigger to the App-installation Service (the secret that
	// just verified the HMAC). An unregistered App is a misconfiguration: log
	// and ignore rather than act unattributed.
	principal, err := s.dc.Auth.ResolveService(s.secretSHA)
	if err != nil {
		s.audit("github_event_unattributed", evt, map[string]any{"reason": "no service for webhook secret"})
		return nil
	}

	repos, err := s.host.InstallationRepos(ctx)
	if err != nil {
		return fmt.Errorf("github: installation repos: %w", err)
	}
	decision := Gate(evt.Repo, GatePolicy{
		AutoEnroll:        s.opts.AutoEnroll,
		InstallationRepos: repos,
		EnabledRepos:      s.opts.EnabledRepos,
	})
	if decision != Act {
		s.audit("github_pr_ignored", evt, map[string]any{
			"principal":   principal.ID,
			"auto_enroll": s.opts.AutoEnroll,
		})
		return nil
	}

	return s.reviewPR(ctx, evt, principal)
}

// reviewPR runs an automatic PR review for an enabled repo. A Session keyed by
// (github, repo + PR number) clones at the PR head with the installation token
// (private repos work), drives the scanner-backed agent loop, and posts the
// findings as a single summary review comment by argus[bot]. The review is
// attributed to the App-installation Service with the PR author kept as
// metadata; the agent persists the Report via finalize_report.
func (s *Server) reviewPR(ctx context.Context, evt Event, principal auth.Principal) error {
	repo := codehost.Repo{
		Host:     "github.com",
		Owner:    evt.Owner,
		Name:     evt.Name,
		FullName: evt.Repo,
	}

	co, err := s.host.Clone(ctx, repo, evt.HeadSHA)
	if err != nil {
		return fmt.Errorf("github: clone PR head: %w", err)
	}

	// One stable session identity per (repo, PR) so later comment turns
	// re-attach to this same review context (ADR 0008 / slice 5).
	sess, _, err := s.dc.Sessions.GetOrCreate(ctx, s.Name(), prConversationKey(evt), principal, daemon.SessionOptions{})
	if err != nil {
		return fmt.Errorf("github: session: %w", err)
	}
	defer s.dc.Sessions.Release(sess)

	rep, _, err := sess.HandlePRReview(ctx, daemon.PRReviewTarget{
		Repo:   evt.Repo,
		Number: evt.Number,
		Path:   co.Path,
		SHA:    co.SHA,
	}, daemon.RunCallbacks{})
	if err != nil {
		return fmt.Errorf("github: PR review: %w", err)
	}

	if err := s.host.PostComment(ctx, repo, evt.Number, summaryComment(rep)); err != nil {
		return fmt.Errorf("github: post review: %w", err)
	}

	findings := 0
	if rep != nil {
		findings = len(rep.Findings)
	}
	s.audit("github_pr_reviewed", evt, map[string]any{
		"principal": principal.ID,    // the App-installation Service (trigger)
		"pr_author": evt.Author,      // the PR author, as metadata
		"identity":  principal.Identity,
		"head_sha":  co.SHA,
		"findings":  findings,
	})
	return nil
}

// prConversationKey is the stable session key for a PR: repo + PR number, so
// the auto-review and every later comment map to one Session identity.
func prConversationKey(evt Event) string {
	return fmt.Sprintf("%s#%d", evt.Repo, evt.Number)
}

// summaryComment renders the review Report as the body of the single summary
// comment argus[bot] posts on the PR. Slice 2 lists every finding in the body;
// inline placement on changed lines arrives in the next slice.
func summaryComment(rep *report.Report) string {
	var b strings.Builder
	b.WriteString("## 🛡️ Argus security review\n\n")

	if rep != nil {
		if sum := strings.TrimSpace(rep.Summary); sum != "" {
			b.WriteString(sum + "\n\n")
		}
	}

	if rep == nil || len(rep.Findings) == 0 {
		b.WriteString("No security findings.\n")
		return b.String()
	}

	fmt.Fprintf(&b, "**%d finding(s):**\n\n", len(rep.Findings))
	for _, f := range rep.Findings {
		fmt.Fprintf(&b, "- **[%s]** %s", strings.ToUpper(f.Severity), f.Title)
		if loc := location(f); loc != "" {
			fmt.Fprintf(&b, " — `%s`", loc)
		}
		b.WriteString("\n")
	}
	return b.String()
}

// location renders a finding's file[:line], or "" when no file is known.
func location(f report.Finding) string {
	if f.File == "" {
		return ""
	}
	if f.Line > 0 {
		return fmt.Sprintf("%s:%d", f.File, f.Line)
	}
	return f.File
}

// audit records a channel event attributed to the GitHub channel.
func (s *Server) audit(typ string, evt Event, extra map[string]any) {
	data := map[string]any{
		"channel":   s.Name(),
		"repo":      evt.Repo,
		"pr_number": evt.Number,
	}
	maps.Copy(data, extra)
	_ = s.dc.Audit.Log(audit.Event{Type: typ, Data: data})
}

// compile-time check that the channel satisfies daemon.Channel.
var _ daemon.Channel = (*Server)(nil)
