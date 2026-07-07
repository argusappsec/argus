package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/argusappsec/argus/pkg/agent"
	"github.com/argusappsec/argus/pkg/audit"
	"github.com/argusappsec/argus/pkg/auth"
	"github.com/argusappsec/argus/pkg/budget"
	"github.com/argusappsec/argus/pkg/codehost"
	"github.com/argusappsec/argus/pkg/codehost/github"
	"github.com/argusappsec/argus/pkg/conversation"
	"github.com/argusappsec/argus/pkg/provider"
	"github.com/argusappsec/argus/pkg/report"
	"github.com/argusappsec/argus/pkg/security"
	"github.com/argusappsec/argus/pkg/session"
	"github.com/argusappsec/argus/pkg/soul"
	"github.com/argusappsec/argus/pkg/tool"
)

// ErrRunInProgress is returned when a second dispatch lands on a Session
// whose agent run is still in flight. One run per Session, no buffering —
// queueing follow-ups is a channel-level choice if it ever becomes one.
var ErrRunInProgress = errors.New("daemon: a run is already in progress for this session")

// ErrUnknownSkill is returned when a "/<name>" message names no skill in the
// organization's catalog.
var ErrUnknownSkill = errors.New("daemon: unknown skill")

// RunCallbacks stream one agent run back to the owning channel.
type RunCallbacks struct {
	// OnMessage receives every message appended to the run's history.
	OnMessage func(provider.Message)
	// OnUsage receives per-LLM-call token usage with the daemon-computed
	// USD cost (clients never see the pricing table).
	OnUsage func(u provider.Usage, costUSD float64)
}

// ReviewTarget is the structured, deterministic way to start a review:
// the daemon clones and pins the Session's root itself — starting a review
// never depends on the model choosing to call a tool. `argus review`
// exercises it today; the webhook channel will rely on it.
type ReviewTarget struct {
	GitHubURL string
	Ref       string
}

// Session is one running conversation between a Principal and the agent.
// It owns the per-run mutable state: tool root, conversation log, provider,
// usage counters. Created only by SessionManager.GetOrCreate.
type Session struct {
	id        string
	channel   string
	principal auth.Principal
	modelID   string
	maxTurns  int
	ephemeral bool // one-shot Session: skip end-of-session memory curation

	dc        *Context
	toolState *session.Session
	convo     *conversation.Writer
	convoPath string
	provider  provider.Provider
	registry  *tool.Registry
	audit     *audit.Logger
	soul      *soul.Soul
	memory    string

	mu       sync.Mutex
	running  bool
	userMsgs int

	usageMu   sync.Mutex
	tokensIn  int
	tokensOut int
	costUSD   float64
}

// ID returns the session identifier (hash of channel + conversation key).
func (s *Session) ID() string { return s.id }

// SetToolRoot points the Session's file-scoped tools (list_files, read_file,
// grep, run_semgrep, …) at path. The review paths set it from their checkout;
// the GitHub channel's rescope action sets it after cloning the PR head so the
// in-thread focused pass can read the tree.
func (s *Session) SetToolRoot(path string) { s.toolState.SetRoot(path) }

// Principal returns the resolved actor that owns this Session.
func (s *Session) Principal() auth.Principal { return s.principal }

// ConversationPath returns the on-disk conversation log location.
func (s *Session) ConversationPath() string { return s.convoPath }

// HandleMessage dispatches one user message: skill resolution for "/<name>"
// lines (against the daemon's catalog — the same on every channel), history
// re-seed from the conversation log, then one agent run.
func (s *Session) HandleMessage(ctx context.Context, text string, cb RunCallbacks) (*report.Report, error) {
	return s.handleMessage(ctx, text, s.registry, cb)
}

// HandleComment is HandleMessage with extra, request-scoped tools available only
// to this turn. The tools are layered onto a per-run copy of the registry, never
// the shared one, so their per-turn dependencies and authorization (e.g. the
// GitHub channel's suppress_finding / rescope_review, bound to the commenter's
// Role) cannot race or leak into another concurrent turn on the same Session.
func (s *Session) HandleComment(ctx context.Context, text string, extraTools []tool.Tool, cb RunCallbacks) (*report.Report, error) {
	return s.handleMessage(ctx, text, s.registry.With(extraTools...), cb)
}

// handleMessage is the shared body of HandleMessage / HandleComment: it runs one
// turn against the given tool registry.
func (s *Session) handleMessage(ctx context.Context, text string, registry *tool.Registry, cb RunCallbacks) (*report.Report, error) {
	if err := s.beginRun(); err != nil {
		return nil, err
	}
	defer s.endRun()

	prompt := strings.TrimSpace(text)
	if strings.HasPrefix(prompt, "/") {
		resolved, err := s.resolveSkill(prompt)
		if err != nil {
			return nil, err
		}
		prompt = resolved
	}

	seed, userMsg, err := s.seedWith(prompt)
	if err != nil {
		return nil, err
	}
	if err := s.convo.Append(conversation.Record{Message: userMsg}); err != nil {
		return nil, fmt.Errorf("daemon: persist user message: %w", err)
	}
	s.countUserMessage()

	return s.run(ctx, seed, agent.Target{}, registry, s.dc.Reports, cb)
}

// HandleReview deterministically starts a review: clone on the daemon host,
// pin the Session root, seed the standard review prompt, run. Returns the
// report and the path of the report file when one was written.
func (s *Session) HandleReview(ctx context.Context, target ReviewTarget, cb RunCallbacks) (*report.Report, string, error) {
	if err := s.beginRun(); err != nil {
		return nil, "", err
	}
	defer s.endRun()

	u, err := github.ParseURL(target.GitHubURL)
	if err != nil {
		return nil, "", fmt.Errorf("daemon: review target: %w", err)
	}
	co, err := s.dc.Cloner.Clone(ctx, u, target.Ref)
	if err != nil {
		return nil, "", fmt.Errorf("daemon: clone: %w", err)
	}

	seedPrompt := fmt.Sprintf(
		"Please run a thorough security review of %s at commit %s. "+
			"The repository is already checked out locally — use list_files / read_file / "+
			"grep / run_semgrep / run_gitleaks / run_osv_scanner freely. Record each issue you confirm via "+
			"add_finding, then call finalize_report with a concise summary when you are done. "+
			"If something is genuinely ambiguous, ask me; otherwise proceed autonomously.",
		u.FullName, co.SHA,
	)
	return s.runReviewTarget(ctx, agent.Target{Repo: u.FullName, SHA: co.SHA, Path: co.Path}, seedPrompt, cb)
}

// PRReviewTarget describes an automatic pull-request review. The channel
// clones at the PR head with the installation token (so private repos work)
// and hands the checkout to the Session — unlike HandleReview, which clones
// anonymously on the daemon host. The Session pins the checkout, stashes the
// pre-fetched PR diff for the pr_diff tool, seeds a prompt that signals "PR
// review", and runs. The scanners cover the whole head checkout for accuracy;
// the agent judges PR-relevance from the diff (ADR 0009).
type PRReviewTarget struct {
	Repo    string          // canonical "github.com/<owner>/<name>"
	Number  int             // PR number
	Path    string          // local checkout at the head SHA (cloned by the channel)
	SHA     string          // resolved head commit SHA
	BaseSHA string          // PR base commit SHA
	Diff    codehost.PRDiff // changed files + hunks, pre-fetched by the channel
}

// HandlePRReview runs one automatic PR review against an already-cloned head
// checkout: pin the Session root, seed the PR-review prompt, run. Returns the
// report and the path of the report file when one was written.
func (s *Session) HandlePRReview(ctx context.Context, target PRReviewTarget, cb RunCallbacks) (*report.Report, string, error) {
	if err := s.beginRun(); err != nil {
		return nil, "", err
	}
	defer s.endRun()

	// Stash the pre-fetched diff so the pr_diff tool can hand the changed files
	// and hunks to the agent for the relevance judgement (ADR 0009).
	s.toolState.SetPRDiff(target.Diff)

	seedPrompt := fmt.Sprintf(
		"You are running an automated security review of pull request #%d of %s. "+
			"The repository is already checked out locally at the PR head commit %s — use "+
			"list_files / read_file / grep / run_semgrep / run_gitleaks / run_osv_scanner freely "+
			"over the WHOLE tree for accuracy. Then call pr_diff to see which files and lines this "+
			"pull request changed, and report a finding ONLY when it is on a changed line OR is "+
			"causally tied to the change (the diff calls an insecure function defined elsewhere, "+
			"bumps a dependency to a vulnerable version, etc.). Do NOT report the repository's "+
			"pre-existing issues unrelated to this change. Record each relevant issue via add_finding "+
			"(set file and line so it can be placed inline), then call finalize_report with a concise "+
			"summary suitable for posting on the pull request. Proceed autonomously.",
		target.Number, target.Repo, target.SHA,
	)
	return s.runReviewTarget(ctx, agent.Target{
		Repo:     target.Repo,
		SHA:      target.SHA,
		Path:     target.Path,
		PRNumber: target.Number,
		BaseSHA:  target.BaseSHA,
	}, seedPrompt, cb)
}

// HandleSnapshotReview runs an org-aware Snapshot review (ADR 0011) over a
// scratch workspace of caller-supplied files. Unlike HandleReview /
// HandlePRReview the daemon never clones: the workspace is materialized by the
// MCP channel from content the external AI handed over, and pointed at the
// agent's file-scoped tools and scanners as agent.Target.Path with empty
// Repo/SHA — a Snapshot review has no repo or commit. The agent runs the same
// org-aware loop (SOUL/MEMORY in the system prompt, real scanners), and its
// findings come back through the normal report.Finding pipeline. They are
// returned to the caller in the MCP response rather than persisted as a report
// file, so the reports writer is intentionally nil for this run.
func (s *Session) HandleSnapshotReview(ctx context.Context, snapshotPath string, rec session.MissRecorder, cb RunCallbacks) (*report.Report, error) {
	if err := s.beginRun(); err != nil {
		return nil, err
	}
	defer s.endRun()

	s.toolState.SetRoot(snapshotPath)
	// Wire the workspace in as the miss recorder so a read of a file the caller
	// did not supply is recorded (and surfaces as files_needed) instead of being
	// a hard error — this is what keeps the review collaborative (ADR 0011).
	s.toolState.SetMissRecorder(rec)

	seedPrompt := "You are running an organization-aware security review of a code Snapshot a " +
		"developer handed you through their AI assistant. The changed files are already " +
		"materialized locally — use list_files / read_file / grep / run_semgrep / run_gitleaks / " +
		"run_osv_scanner freely over the workspace. Judge the code through THIS organization's lens " +
		"(its stack, conventions, risk tolerance, and the false positives already accepted in SOUL/MEMORY), " +
		"not a generic checklist. " +
		"IMPORTANT — reach for the call chain: when deciding whether a handler is safe depends on code you " +
		"were not given (a helper, middleware, base repository, policy, or a dependency manifest like go.mod / " +
		"package.json), do NOT assume it is correct. Try to read it with read_file using its repo-relative path " +
		"(e.g. internal/guard/guard.go). A path the snapshot does not hold is not an error — it is recorded and " +
		"returned to the developer as a files_needed request, who will supply it so you can finish. Never " +
		"approve an authorization/ownership guard you have not actually read. " +
		"Record each issue you confirm via add_finding (set file and line), then " +
		"call finalize_report with a concise summary. Proceed autonomously."

	seed, userMsg, err := s.seedWith(seedPrompt)
	if err != nil {
		return nil, err
	}
	if err := s.convo.Append(conversation.Record{Message: userMsg}); err != nil {
		return nil, fmt.Errorf("daemon: persist seed: %w", err)
	}
	s.countUserMessage()

	return s.run(ctx, seed, agent.Target{Path: snapshotPath}, s.registry, nil, cb)
}

// HandleConsult runs an org-aware Q&A turn (ADR 0011): the caller's question is
// answered from the organization's security knowledge (SOUL/MEMORY in the system
// prompt, the CONTEXT documents via list_context / read_context) with NO code
// target — there is nothing to scan, so the agent answers in prose rather than
// recording findings. The answer is the model's text, which the channel captures
// through the run callbacks; no report file is written (reports is nil), so the
// consultation is transient like a Snapshot review. Reuses the same org-aware
// agent invocation plumbing as the review paths.
func (s *Session) HandleConsult(ctx context.Context, question string, cb RunCallbacks) (*report.Report, error) {
	if err := s.beginRun(); err != nil {
		return nil, err
	}
	defer s.endRun()

	seedPrompt := "A developer has asked you, through their AI assistant, a security question that needs THIS " +
		"organization's context to answer well — its stack, conventions, infra, compliance posture, risk " +
		"tolerance, and the decisions recorded in SOUL/MEMORY and the CONTEXT documents. Use list_context / " +
		"read_context to consult the organization's documents as needed and answer grounded in what you find, " +
		"not generic security education (the developer's own AI already covers textbook questions). There is no " +
		"code to review here: do not call add_finding or finalize_report — just answer in prose. The question:\n\n" +
		question

	seed, userMsg, err := s.seedWith(seedPrompt)
	if err != nil {
		return nil, err
	}
	if err := s.convo.Append(conversation.Record{Message: userMsg}); err != nil {
		return nil, fmt.Errorf("daemon: persist consult question: %w", err)
	}
	s.countUserMessage()

	return s.run(ctx, seed, agent.Target{}, s.registry, nil, cb)
}

// runReviewTarget is the shared review spine for HandleReview and
// HandlePRReview: pin the checkout as the tool root, seed and persist the
// prompt, run one agent loop, and resolve the report file path the run may have
// written. The callers differ only in where the checkout comes from (anonymous
// daemon clone vs. the channel's installation-token clone), the PR-awareness of
// the Target, and the seed prompt.
func (s *Session) runReviewTarget(ctx context.Context, target agent.Target, seedPrompt string, cb RunCallbacks) (*report.Report, string, error) {
	s.toolState.SetRoot(target.Path)

	seed, userMsg, err := s.seedWith(seedPrompt)
	if err != nil {
		return nil, "", err
	}
	if err := s.convo.Append(conversation.Record{Message: userMsg}); err != nil {
		return nil, "", fmt.Errorf("daemon: persist seed: %w", err)
	}
	s.countUserMessage()

	rep, err := s.run(ctx, seed, target, s.registry, s.dc.Reports, cb)
	if err != nil {
		return nil, "", err
	}

	reportPath := s.dc.Reports.PathFor(target.Repo, target.SHA)
	if _, statErr := os.Stat(reportPath); statErr != nil {
		reportPath = "" // run ended without finalize_report writing a file
	}
	return rep, reportPath, nil
}

// run executes one agent run with this Session's snapshots and streams it
// through cb. reports may be nil — a Snapshot review (ADR 0011) returns its
// findings to the MCP caller transiently and writes no report file.
func (s *Session) run(ctx context.Context, seed []provider.Message, target agent.Target, registry *tool.Registry, reports *report.Writer, cb RunCallbacks) (*report.Report, error) {
	ag := agent.New(agent.Options{
		Provider:     s.provider,
		Audit:        s.audit,
		Reports:      reports,
		Tools:        registry,
		Conversation: s.convo,
		Soul:         s.soul,
		Memory:       s.memory,
		MaxTurns:     s.maxTurns,
		SeedMessages: seed,
		OnMessage: func(m provider.Message) {
			if cb.OnMessage != nil {
				cb.OnMessage(m)
			}
		},
		OnUsage: func(u provider.Usage) {
			cost := budget.CostFor(s.dc.Pricing, s.modelID, u.InputTokens, u.OutputTokens)
			s.recordUsage(u, cost)
			if cb.OnUsage != nil {
				cb.OnUsage(u, cost)
			}
		},
	})
	return ag.Run(ctx, target)
}

// seedWith re-reads the conversation log and appends the new user message,
// returning the full seed plus the user message (which the caller persists —
// the agent skips persistence of caller-provided seeds).
func (s *Session) seedWith(prompt string) ([]provider.Message, provider.Message, error) {
	prev, err := conversation.ReadAll(s.convoPath)
	if err != nil {
		return nil, provider.Message{}, fmt.Errorf("daemon: read history: %w", err)
	}
	seed := make([]provider.Message, 0, len(prev)+1)
	for _, r := range prev {
		seed = append(seed, r.Message)
	}
	userMsg := provider.Message{Role: "user", Content: prompt}
	return append(seed, userMsg), userMsg, nil
}

// resolveSkill maps a raw "/<name> ..." line to the skill-invocation prompt,
// using the organization's catalog on the daemon host. Client-side commands
// never reach this point — they never leave the client.
func (s *Session) resolveSkill(line string) (string, error) {
	name := strings.TrimPrefix(strings.Fields(line)[0], "/")
	sk, err := s.dc.Skills.Load(name)
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrUnknownSkill, name)
	}
	return fmt.Sprintf(
		"Use the %q skill for this task. Follow these instructions:\n\n%s",
		sk.Name, sk.Content,
	), nil
}

func (s *Session) beginRun() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return ErrRunInProgress
	}
	s.running = true
	return nil
}

func (s *Session) endRun() {
	s.mu.Lock()
	s.running = false
	s.mu.Unlock()
}

func (s *Session) countUserMessage() {
	s.mu.Lock()
	s.userMsgs++
	s.mu.Unlock()
}

func (s *Session) userMessages() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.userMsgs
}

func (s *Session) recordUsage(u provider.Usage, cost float64) {
	s.usageMu.Lock()
	s.tokensIn += u.InputTokens
	s.tokensOut += u.OutputTokens
	s.costUSD += cost
	s.usageMu.Unlock()
}

// Usage returns the Session's cumulative token and cost counters.
func (s *Session) Usage() (tokensIn, tokensOut int, costUSD float64) {
	s.usageMu.Lock()
	defer s.usageMu.Unlock()
	return s.tokensIn, s.tokensOut, s.costUSD
}

// buildRegistry assembles the per-Session tool registry around its tool
// state. Mirrors what the single-process CLI used to register; new tools are
// added here once and every channel sees them.
func buildRegistry(toolState *session.Session, dc *Context) *tool.Registry {
	reg := tool.NewRegistry()
	reg.Register(tool.NewListFiles(toolState))
	reg.Register(tool.NewReadFile(toolState))
	reg.Register(tool.NewGrep(toolState))
	reg.Register(tool.NewListContext(contextDir(dc)))
	reg.Register(tool.NewReadContext(contextDir(dc)))
	reg.Register(tool.NewWriteContext(contextDir(dc)))
	reg.Register(tool.NewStartReviewLocal(toolState))
	reg.Register(tool.NewStartReviewGitHub(toolState, dc.Cloner))
	reg.Register(tool.NewPRDiff(toolState))
	reg.Register(security.NewSemgrep(toolState, security.ExecRunner{}))
	reg.Register(security.NewGitleaks(toolState, security.ExecRunner{}))
	reg.Register(security.NewOSVScanner(toolState, security.ExecRunner{}))
	reg.Register(tool.NewListSkills(dc.Skills))
	reg.Register(tool.NewReadSkill(dc.Skills))
	reg.Register(tool.NewReadSkillFile(dc.Skills))
	return reg
}

func contextDir(dc *Context) string {
	return filepath.Join(dc.Home, "context")
}

func auditEvent(typ string, data map[string]any) audit.Event {
	return audit.Event{Type: typ, Data: data}
}
