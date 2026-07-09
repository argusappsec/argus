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
	"sync"
	"time"

	"github.com/argusappsec/argus/pkg/audit"
	"github.com/argusappsec/argus/pkg/auth"
	"github.com/argusappsec/argus/pkg/codehost"
	"github.com/argusappsec/argus/pkg/daemon"
	"github.com/argusappsec/argus/pkg/provider"
	"github.com/argusappsec/argus/pkg/report"
	"github.com/argusappsec/argus/pkg/tool"
)

// maxBodyBytes bounds the webhook payload we read into memory.
const maxBodyBytes = 8 << 20 // 8 MiB

// Options carries the channel's resolved configuration.
type Options struct {
	Addr          string   // HTTP listen address
	WebhookSecret string   // resolved App webhook secret (raw)
	AutoEnroll    bool     // effective github.auto_enroll
	EnabledRepos  []string // explicit allow-list when AutoEnroll is false
	PersonaName   string   // operator-chosen name (persona.name); adds @<name> as a mention token
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
	reviews   *prReviewStore

	// mentions is the set of @-handles a comment may use to address this
	// instance (@argus plus any configured persona handle), computed once at
	// construction rather than per event.
	mentions []string
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
		reviews:   newPRReviewStore(dc.Home),
		mentions:  mentionTokens(opts.PersonaName),
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

// dispatch routes a verified event. An opened or synchronized PR runs an
// automatic diff-aware review; a synchronize replaces the bot's prior review
// rather than stacking a new one (ADR 0009). A comment carrying the @argus
// mention from a resolved Person becomes a conversational turn in the thread.
func (s *Server) dispatch(ctx context.Context, evt Event) error {
	// The installation the App should act as is carried in the event payload
	// (ADR 0015): seed it so every clone/API call for this repo mints a token
	// for that installation without an extra App-JWT lookup. Multi-org support
	// is then free — a different org's event simply carries a different id.
	if evt.InstallationID != "" {
		if noter, ok := s.host.(installationNoter); ok {
			noter.NoteInstallation(repoFromEvent(evt), evt.InstallationID)
		}
	}
	switch evt.Kind {
	case KindPullRequest:
		return s.dispatchPullRequest(ctx, evt)
	case KindComment:
		return s.dispatchComment(ctx, evt)
	default:
		return nil
	}
}

// installationNoter is optionally implemented by a CodeHost that can be told a
// repo's installation up-front (from a webhook event), skipping the per-repo
// App-JWT resolution. The GitHub CodeHost implements it; a test fake need not.
type installationNoter interface {
	NoteInstallation(repo codehost.Repo, installationID string)
}

// dispatchPullRequest handles an opened/synchronize PR: attribute the trigger
// to the App-installation Service, gate on the enabled-repo policy, then run
// the automatic review.
func (s *Server) dispatchPullRequest(ctx context.Context, evt Event) error {
	if evt.Action != "opened" && evt.Action != "synchronize" {
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

	repos, err := s.host.InstallationRepos(ctx, repoFromEvent(evt))
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

// dispatchComment handles a PR/issue comment as a conversational turn (ADR
// 0008, slice 5). The channel parses the @argus mention itself and resolves
// the commenter's github:<login> to a Person; a comment without the mention,
// or from a login that resolves to no Person, is silently ignored — no reply,
// no leak that Argus exists. A resolved Person's turn re-hydrates the PR's
// Session from its on-disk conversation log (continuity via the log, not a
// resident in-memory session), runs one agent turn attributed to that Person
// with their Role, and posts the agent's answer back in the thread.
func (s *Server) dispatchComment(ctx context.Context, evt Event) error {
	request, ok := parseMention(evt.Body, s.mentions)
	if !ok {
		return nil // not addressed to Argus — silently ignored (ADR 0008)
	}

	identity := "github:" + evt.Commenter
	principal, err := s.dc.Auth.Resolve(identity)
	if err != nil {
		// An unregistered commenter is silently ignored on the wire; the audit
		// log still records the ignore for the operator.
		s.audit("github_comment_ignored", evt, map[string]any{
			"reason": "unresolved login",
			"login":  evt.Commenter,
		})
		return nil
	}

	// One stable Session identity per (repo, PR): the same key the automatic
	// review used, so the turn re-hydrates that review's context from the log.
	sess, _, err := s.dc.Sessions.GetOrCreate(ctx, s.Name(), prConversationKey(evt), principal, daemon.SessionOptions{})
	if err != nil {
		return fmt.Errorf("github: session: %w", err)
	}
	defer s.dc.Sessions.Release(sess)

	repo := repoFromEvent(evt)

	// The PR comment-action tools for this turn. They carry the channel's
	// CodeHost and per-PR review state, and enforce RBAC themselves (ADR 0008 /
	// slice 6): an analyst+ can suppress a finding or re-scope the analysis; a
	// viewer's call is refused at the tool layer, keeping them explain-only. They
	// are bound to this commenter's Role and passed per-turn (not registered on
	// the shared Session) so a concurrent turn cannot run with the wrong actor.
	actionTools := []tool.Tool{
		&suppressFinding{
			role:           principal.Role,
			store:          s.reviews,
			host:           s.host,
			repo:           repo,
			number:         evt.Number,
			recordAdvisory: s.dc.Sessions.AppendMemory,
		},
		&rescopeReview{
			role:    principal.Role,
			store:   s.reviews,
			host:    s.host,
			repo:    repo,
			number:  evt.Number,
			setRoot: sess.SetToolRoot,
		},
	}

	// The mention-stripped request is what the agent acts on; fall back to the
	// raw body for a bare mention (the comment was only the handle) so the user
	// message is never empty.
	text := request
	if text == "" {
		text = evt.Body
	}

	var reply replyCapture
	if _, err := sess.HandleComment(ctx, text, actionTools, daemon.RunCallbacks{OnMessage: reply.onMessage}); err != nil {
		return fmt.Errorf("github: comment turn: %w", err)
	}

	if err := s.host.PostComment(ctx, repo, evt.Number, reply.body()); err != nil {
		return fmt.Errorf("github: post reply: %w", err)
	}

	s.audit("github_comment_replied", evt, map[string]any{
		"principal": principal.ID,
		"identity":  principal.Identity,
		"role":      string(principal.Role),
		"commenter": evt.Commenter,
	})
	return nil
}

// reviewPR runs an automatic diff-aware PR review for an enabled repo. A
// Session keyed by (github, repo + PR number) clones at the PR head with the
// installation token (private repos work), fetches the PR diff (so the agent
// can judge relevance via the pr_diff tool — ADR 0009), drives the
// scanner-backed agent loop, then posts the findings as argus[bot]: each
// finding on a changed line as an inline comment, causal off-diff findings in
// the summary body. A synchronize replaces the bot's prior review. The review
// is attributed to the App-installation Service with the PR author kept as
// metadata; the agent persists the Report via finalize_report.
func (s *Server) reviewPR(ctx context.Context, evt Event, principal auth.Principal) error {
	repo := repoFromEvent(evt)

	co, err := s.host.Clone(ctx, repo, evt.HeadSHA)
	if err != nil {
		return fmt.Errorf("github: clone PR head: %w", err)
	}

	diff, err := s.host.FetchPRDiff(ctx, repo, evt.Number)
	if err != nil {
		return fmt.Errorf("github: fetch PR diff: %w", err)
	}

	// One stable session identity per (repo, PR) so later comment turns
	// re-attach to this same review context (ADR 0008 / slice 5).
	sess, _, err := s.dc.Sessions.GetOrCreate(ctx, s.Name(), prConversationKey(evt), principal, daemon.SessionOptions{})
	if err != nil {
		return fmt.Errorf("github: session: %w", err)
	}
	defer s.dc.Sessions.Release(sess)

	rep, _, err := sess.HandlePRReview(ctx, daemon.PRReviewTarget{
		Repo:    evt.Repo,
		Number:  evt.Number,
		Path:    co.Path,
		SHA:     co.SHA,
		BaseSHA: evt.BaseSHA,
		Diff:    diff,
	}, daemon.RunCallbacks{})
	if err != nil {
		return fmt.Errorf("github: PR review: %w", err)
	}

	// Persist the review as this PR's state (keyed by repo + PR number, findable
	// from a later comment turn), preserving any findings a teammate already
	// suppressed on this PR so the suppression survives this re-review (slice 6).
	state, err := s.reviews.Load(evt.Repo, evt.Number)
	if err != nil {
		return err
	}
	// rep is non-nil here: HandlePRReview returns a nil report only with an
	// error, which is handled above.
	state.HeadSHA = co.SHA
	state.Summary = rep.Summary
	state.Findings = rep.Findings
	if err := s.reviews.Save(evt.Repo, evt.Number, state); err != nil {
		return err
	}

	// Render and post the live findings (everything minus the PR-local hard
	// suppressions). A synchronize replaces the bot's prior review instead of
	// stacking a new one.
	live := state.LiveFindings()
	review := renderReview(co.SHA, state.Summary, live, diff)
	if err := s.host.PostReview(ctx, repo, evt.Number, review, evt.Action == "synchronize"); err != nil {
		return fmt.Errorf("github: post review: %w", err)
	}

	s.audit("github_pr_reviewed", evt, map[string]any{
		"principal":  principal.ID, // the App-installation Service (trigger)
		"pr_author":  evt.Author,   // the PR author, as metadata
		"identity":   principal.Identity,
		"head_sha":   co.SHA,
		"action":     evt.Action,
		"findings":   len(state.Findings),
		"suppressed": len(state.Suppressed),
		"inline":     len(review.Inline),
	})
	return nil
}

// renderReview assembles the GitHub review argus[bot] posts from a head SHA, the
// agent's summary, and the findings to post (already minus any PR-local
// suppressions). Findings on a changed line become inline comments; causal
// off-diff findings go in the summary body GitHub cannot attach inline.
func renderReview(headSHA, summary string, findings []report.Finding, diff codehost.PRDiff) codehost.Review {
	inline, offDiff := splitFindings(findings, diff)
	return codehost.Review{
		HeadSHA: headSHA,
		Summary: summaryComment(summary, len(findings), offDiff),
		Inline:  inline,
	}
}

// splitFindings partitions a report's findings by diff placement: those on a
// changed line become inline review comments; the rest (causal off-diff
// findings GitHub cannot attach inline) are returned for the summary body.
func splitFindings(findings []report.Finding, diff codehost.PRDiff) (inline []codehost.InlineComment, offDiff []report.Finding) {
	for _, f := range findings {
		if diff.IsChangedLine(f.File, f.Line) {
			inline = append(inline, codehost.InlineComment{
				Path: f.File,
				Line: f.Line,
				Body: inlineBody(f),
			})
			continue
		}
		offDiff = append(offDiff, f)
	}
	return inline, offDiff
}

// inlineBody renders one finding as the body of an inline review comment.
func inlineBody(f report.Finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "**[%s] %s**", strings.ToUpper(f.Severity), findingTitle(f))
	if f.Description != "" {
		fmt.Fprintf(&b, "\n\n%s", f.Description)
	}
	if f.Remediation != "" {
		fmt.Fprintf(&b, "\n\n**Remediation:** %s", f.Remediation)
	}
	return b.String()
}

// findingTitle is the finding's title, falling back to its rule id.
func findingTitle(f report.Finding) string {
	if f.Title != "" {
		return f.Title
	}
	return f.RuleID
}

// prConversationKey is the stable session key for a PR: repo + PR number, so
// the auto-review and every later comment map to one Session identity.
func prConversationKey(evt Event) string {
	return fmt.Sprintf("%s#%d", evt.Repo, evt.Number)
}

// repoFromEvent builds the CodeHost Repo a delivery refers to.
func repoFromEvent(evt Event) codehost.Repo {
	return codehost.Repo{
		Host:     "github.com",
		Owner:    evt.Owner,
		Name:     evt.Name,
		FullName: evt.Repo,
	}
}

// summaryComment renders the body of the single summary comment argus[bot]
// posts on the PR. Findings on changed lines are posted as inline comments
// instead (passed separately to PostReview); the summary body carries the
// agent's narrative, a pointer to the inline comments, and the causal off-diff
// findings GitHub cannot attach inline (ADR 0009).
func summaryComment(summary string, total int, offDiff []report.Finding) string {
	var b strings.Builder
	b.WriteString("## 🛡️ Argus security review\n\n")

	if sum := strings.TrimSpace(summary); sum != "" {
		b.WriteString(sum + "\n\n")
	}

	if total == 0 {
		b.WriteString("No security findings.\n")
		return b.String()
	}

	if inline := total - len(offDiff); inline > 0 {
		fmt.Fprintf(&b, "**%d finding(s) on changed lines** — see the inline comments below.\n\n", inline)
	}

	if len(offDiff) > 0 {
		b.WriteString("**Issues related to this change, but not on a changed line:**\n\n")
		for _, f := range offDiff {
			fmt.Fprintf(&b, "- **[%s]** %s", strings.ToUpper(f.Severity), findingTitle(f))
			if loc := location(f); loc != "" {
				fmt.Fprintf(&b, " — `%s`", loc)
			}
			b.WriteString("\n")
		}
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

// replyCapture accumulates the agent's text turns during a conversational
// HandleMessage run so the channel can post them back as one threaded reply.
// Tool-call turns carry no prose (empty Content) and are skipped; the agent's
// answer is the model-role text it emits.
type replyCapture struct {
	mu   sync.Mutex
	msgs []string
}

// onMessage is the daemon.RunCallbacks.OnMessage hook: it keeps every non-empty
// model-role message in order.
func (r *replyCapture) onMessage(m provider.Message) {
	if m.Role != "model" {
		return
	}
	if c := strings.TrimSpace(m.Content); c != "" {
		r.mu.Lock()
		r.msgs = append(r.msgs, c)
		r.mu.Unlock()
	}
}

// body renders the captured turns as the comment body, falling back to a short
// notice when the run produced no prose (e.g. it only called tools).
func (r *replyCapture) body() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.msgs) == 0 {
		return "_Argus has nothing to add._"
	}
	return strings.Join(r.msgs, "\n\n")
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
