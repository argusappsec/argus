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
	"time"

	"github.com/redcarbon-dev/argus/pkg/audit"
	"github.com/redcarbon-dev/argus/pkg/codehost"
	"github.com/redcarbon-dev/argus/pkg/daemon"
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

// dispatch routes a verified event. Slice 1 acts only on an opened PR; other
// kinds (synchronize, comments) are accepted but not yet acted on.
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

	repo := codehost.Repo{
		Host:     "github.com",
		Owner:    evt.Owner,
		Name:     evt.Name,
		FullName: evt.Repo,
	}
	if err := s.host.PostComment(ctx, repo, evt.Number, ackBody); err != nil {
		return fmt.Errorf("github: post acknowledgment: %w", err)
	}

	s.audit("github_pr_acknowledged", evt, map[string]any{
		"principal": principal.ID,    // the App-installation Service (trigger)
		"pr_author": evt.Author,      // the PR author, as metadata
		"identity":  principal.Identity,
	})
	return nil
}

// ackBody is the slice-1 acknowledgment comment posted as argus[bot].
const ackBody = "Argus is now watching this pull request. An automated security review will follow."

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
