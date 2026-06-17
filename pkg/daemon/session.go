package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/redcarbon-dev/argus/pkg/agent"
	"github.com/redcarbon-dev/argus/pkg/audit"
	"github.com/redcarbon-dev/argus/pkg/auth"
	"github.com/redcarbon-dev/argus/pkg/budget"
	"github.com/redcarbon-dev/argus/pkg/codehost/github"
	"github.com/redcarbon-dev/argus/pkg/conversation"
	"github.com/redcarbon-dev/argus/pkg/provider"
	"github.com/redcarbon-dev/argus/pkg/report"
	"github.com/redcarbon-dev/argus/pkg/security"
	"github.com/redcarbon-dev/argus/pkg/session"
	"github.com/redcarbon-dev/argus/pkg/soul"
	"github.com/redcarbon-dev/argus/pkg/tool"
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

// Principal returns the resolved actor that owns this Session.
func (s *Session) Principal() auth.Principal { return s.principal }

// ConversationPath returns the on-disk conversation log location.
func (s *Session) ConversationPath() string { return s.convoPath }

// HandleMessage dispatches one user message: skill resolution for "/<name>"
// lines (against the daemon's catalog — the same on every channel), history
// re-seed from the conversation log, then one agent run.
func (s *Session) HandleMessage(ctx context.Context, text string, cb RunCallbacks) (*report.Report, error) {
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

	return s.run(ctx, seed, agent.Target{}, cb)
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
	s.toolState.SetRoot(co.Path)

	seedPrompt := fmt.Sprintf(
		"Please run a thorough security review of %s at commit %s. "+
			"The repository is already checked out locally — use list_files / read_file / "+
			"grep / run_semgrep / run_gitleaks freely. Record each issue you confirm via "+
			"add_finding, then call finalize_report with a concise summary when you are done. "+
			"If something is genuinely ambiguous, ask me; otherwise proceed autonomously.",
		u.FullName, co.SHA,
	)
	seed, userMsg, err := s.seedWith(seedPrompt)
	if err != nil {
		return nil, "", err
	}
	if err := s.convo.Append(conversation.Record{Message: userMsg}); err != nil {
		return nil, "", fmt.Errorf("daemon: persist seed: %w", err)
	}
	s.countUserMessage()

	rep, err := s.run(ctx, seed, agent.Target{Repo: u.FullName, SHA: co.SHA, Path: co.Path}, cb)
	if err != nil {
		return nil, "", err
	}

	reportPath := s.dc.Reports.PathFor(u.FullName, co.SHA)
	if _, statErr := os.Stat(reportPath); statErr != nil {
		reportPath = "" // run ended without finalize_report writing a file
	}
	return rep, reportPath, nil
}

// run executes one agent run with this Session's snapshots and streams it
// through cb.
func (s *Session) run(ctx context.Context, seed []provider.Message, target agent.Target, cb RunCallbacks) (*report.Report, error) {
	ag := agent.New(agent.Options{
		Provider:     s.provider,
		Audit:        s.audit,
		Reports:      s.dc.Reports,
		Tools:        s.registry,
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
	reg.Register(security.NewSemgrep(toolState, security.ExecRunner{}))
	reg.Register(security.NewGitleaks(toolState, security.ExecRunner{}))
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
