// Package agent runs the LLM-driven security review loop.
//
// The loop is intentionally small: each turn we send the running message
// history to the Provider, look at the returned ToolCalls, execute them
// (some are "control" tools handled here, others come from a tool registry
// in later versions), and feed the results back as the next turn. Two
// termination paths exist: the model calls `finalize_report`, or a safety
// net trips (max turns reached, etc.).
package agent

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/redcarbon-dev/argus/pkg/audit"
	"github.com/redcarbon-dev/argus/pkg/conversation"
	"github.com/redcarbon-dev/argus/pkg/provider"
	"github.com/redcarbon-dev/argus/pkg/report"
	"github.com/redcarbon-dev/argus/pkg/soul"
	"github.com/redcarbon-dev/argus/pkg/tool"
)

// Target identifies the artifact under review.
type Target struct {
	Repo string // canonical repo name e.g. "github.com/foo/bar"
	SHA  string // commit being reviewed
	Path string // local checkout (may be empty in tests that don't read code)

	// PRNumber and BaseSHA are set for a pull-request review (ADR 0009): the PR
	// number and its base commit. Zero/empty for a plain repo review. They make
	// the run PR-aware for audit and seed context; the changed lines themselves
	// reach the agent through the pr_diff tool.
	PRNumber int
	BaseSHA  string
}

// Options bundles the dependencies of an agent run.
type Options struct {
	Provider     provider.Provider
	Audit        *audit.Logger        // optional
	Reports      *report.Writer       // optional: when nil, finalize_report terminates without writing a file
	Tools        *tool.Registry       // env tools (list_files, read_file, grep, ...). May be nil.
	Conversation *conversation.Writer // optional: persists every message to disk for forensic resume.
	Soul         *soul.Soul           // optional: injected into the LLM as system prompt.

	// SeedMessages, if non-empty, replaces the default "Review {repo} at {sha}"
	// user seed. Used by subagent flows (memory curator, future spawn_agent)
	// where the agent is started with a structured task instead of a review.
	SeedMessages []provider.Message

	// OnMessage, if non-nil, is invoked for every message appended to the
	// running history (user seed, model turn, tool result). Used by UIs that
	// stream the conversation to the screen as it unfolds (TUI, future Slack).
	// Errors thrown by the callback are intentionally swallowed: a misbehaving
	// listener must not abort the agent run.
	OnMessage func(provider.Message)

	// OnUsage, if non-nil, is invoked once per LLM call with the token usage
	// of that call. Used by UIs to maintain a cumulative cost/token counter.
	OnUsage func(provider.Usage)

	// Memory is the curated cross-session memory (typically the content of
	// ~/.argus/MEMORY.md). When set, it is appended to the system prompt
	// under a dedicated "# Memory" section so the agent remembers prior
	// sessions' preferences, decisions and accepted exceptions. Updated
	// by the memory-curator subagent at the end of each session.
	Memory string

	MaxTurns int
}

// Agent is the orchestrator. One Agent per run; create a new one per review.
type Agent struct {
	opts Options
}

// New constructs an Agent. MaxTurns defaults to 50 if zero.
func New(opts Options) *Agent {
	if opts.MaxTurns == 0 {
		opts.MaxTurns = 50
	}
	return &Agent{opts: opts}
}

// ErrMaxTurnsExceeded is returned when the safety-net turn cap trips before
// the model calls finalize_report.
var ErrMaxTurnsExceeded = errors.New("agent: max turns exceeded")

// Run drives the loop to completion and returns the produced Report.
func (a *Agent) Run(ctx context.Context, t Target) (*report.Report, error) {
	rep := &report.Report{
		Target:    t.Repo,
		SHA:       t.SHA,
		Timestamp: time.Now().UTC(),
	}

	startData := map[string]any{"repo": t.Repo, "sha": t.SHA}
	if t.PRNumber > 0 {
		startData["pr_number"] = t.PRNumber
		startData["base_sha"] = t.BaseSHA
	}
	if err := a.audit("session_start", startData); err != nil {
		return nil, err
	}

	// Build the initial conversation. When SeedMessages is provided the
	// caller already owns those messages (history from a previous turn,
	// a structured prompt, etc.); we DO NOT replay them through
	// persistMessage — that would duplicate them in the conversation log
	// and re-emit them to the OnMessage listener. The caller is responsible
	// for any persistence of seed messages.
	//
	// When SeedMessages is empty we synthesize the default "Review {repo}
	// at {sha}" prompt and persist it ourselves: the caller never saw it.
	var msgs []provider.Message
	if len(a.opts.SeedMessages) > 0 {
		msgs = append(msgs, a.opts.SeedMessages...)
	} else {
		seedMsg := provider.Message{
			Role:    "user",
			Content: fmt.Sprintf("Review %s at %s.", t.Repo, t.SHA),
		}
		msgs = append(msgs, seedMsg)
		a.persistMessage(seedMsg)
	}

	decls := a.allToolDecls()
	system := a.composeSystemPrompt()

	for turn := 1; turn <= a.opts.MaxTurns; turn++ {
		resp, err := a.opts.Provider.Generate(ctx, provider.Request{System: system, Messages: msgs, Tools: decls})
		if err != nil {
			return nil, fmt.Errorf("turn %d generate: %w", turn, err)
		}
		_ = a.audit("llm_call", map[string]any{
			"turn":          turn,
			"input_tokens":  resp.Usage.InputTokens,
			"output_tokens": resp.Usage.OutputTokens,
		})
		if a.opts.OnUsage != nil {
			a.opts.OnUsage(resp.Usage)
		}

		// Record the model turn so future turns see its context.
		modelMsg := provider.Message{Role: "model", ToolCalls: resp.ToolCalls, Content: resp.Text}
		msgs = append(msgs, modelMsg)
		a.persistMessage(modelMsg)

		// Text-only response (no tool calls) = natural pause point.
		// In chat mode this returns control to the user. In review mode it
		// means the model has nothing actionable to do; we exit instead of
		// burning turns asking it the same question. Same exit path either
		// way; callers distinguish via opts.Reports being nil/non-nil.
		if len(resp.ToolCalls) == 0 {
			_ = a.audit("session_end", map[string]any{"reason": "text_only_response", "findings": len(rep.Findings)})
			return rep, nil
		}

		results := make([]provider.ToolResult, 0, len(resp.ToolCalls))
		for _, tc := range resp.ToolCalls {
			_ = a.audit("tool_call", map[string]any{"turn": turn, "name": tc.Name})

			switch tc.Name {
			case "add_finding":
				if err := addFinding(rep, tc.Args); err != nil {
					results = append(results, provider.ToolResult{CallID: tc.ID, Name: tc.Name, Output: err.Error(), IsError: true})
					continue
				}
				results = append(results, provider.ToolResult{CallID: tc.ID, Name: tc.Name, Output: "ok"})
			case "finalize_report":
				rep.Summary, _ = tc.Args["summary"].(string)
				// Reports is optional: subagent flows (e.g. memory curator)
				// terminate via finalize_report without producing a report file.
				var reportPath string
				if a.opts.Reports != nil {
					path, err := a.opts.Reports.Write(*rep)
					if err != nil {
						return nil, fmt.Errorf("write report: %w", err)
					}
					reportPath = path
					_ = a.audit("session_end", map[string]any{"report_path": path, "findings": len(rep.Findings)})
				} else {
					_ = a.audit("session_end", map[string]any{"findings": len(rep.Findings)})
				}
				// Synthesize an acknowledgment so the TUI (and the
				// conversation log, and any follow-up agent run) sees where
				// the report landed and a short recap of findings. Without
				// this the loop terminates silently and the user has no
				// inline confirmation that anything was saved.
				results = append(results, provider.ToolResult{
					CallID: tc.ID,
					Name:   tc.Name,
					Output: buildFinalizeAck(rep, reportPath),
				})
				toolMsg := provider.Message{Role: "tool", ToolResults: results}
				msgs = append(msgs, toolMsg)
				a.persistMessage(toolMsg)
				return rep, nil
			default:
				out, err := a.dispatchEnvTool(ctx, tc)
				if err != nil {
					results = append(results, provider.ToolResult{CallID: tc.ID, Name: tc.Name, Output: err.Error(), IsError: true})
				} else {
					results = append(results, provider.ToolResult{CallID: tc.ID, Name: tc.Name, Output: out})
				}
			}
		}

		if len(results) > 0 {
			toolMsg := provider.Message{Role: "tool", ToolResults: results}
			msgs = append(msgs, toolMsg)
			a.persistMessage(toolMsg)
		}
	}

	_ = a.audit("session_end", map[string]any{"reason": "max_turns"})
	return nil, ErrMaxTurnsExceeded
}

// addFinding converts an LLM tool call into a structured finding and appends
// it to the report, assigning a stable ID.
func addFinding(rep *report.Report, args map[string]any) error {
	severity, _ := args["severity"].(string)
	ruleID, _ := args["rule_id"].(string)
	file, _ := args["file"].(string)
	snippet, _ := args["snippet"].(string)

	line := 0
	switch v := args["line"].(type) {
	case float64:
		line = int(v)
	case int:
		line = v
	}

	if ruleID == "" {
		return errors.New("add_finding: rule_id required")
	}
	if severity == "" {
		return errors.New("add_finding: severity required")
	}

	f := report.Finding{
		ID:       report.ComputeFindingID(ruleID, snippet),
		Severity: severity,
		RuleID:   ruleID,
		File:     file,
		Line:     line,
		Snippet:  snippet,
	}
	f.Title, _ = args["title"].(string)
	f.Description, _ = args["description"].(string)
	f.Remediation, _ = args["remediation"].(string)

	rep.Findings = append(rep.Findings, f)
	return nil
}

// dispatchEnvTool looks up tc in the registered Tool registry and runs it.
// Returns an error if the registry is nil or the tool is not registered, so
// the agent can surface it as a tool-call error to the model.
func (a *Agent) dispatchEnvTool(ctx context.Context, tc provider.ToolCall) (string, error) {
	if a.opts.Tools == nil {
		return "", fmt.Errorf("unknown tool: %s", tc.Name)
	}
	t, ok := a.opts.Tools.Get(tc.Name)
	if !ok {
		return "", fmt.Errorf("unknown tool: %s", tc.Name)
	}
	return t.Execute(ctx, tc.Args)
}

// allToolDecls returns the env-tool declarations plus the control tools
// (add_finding, finalize_report) that the agent loop handles directly. We
// surface control tools in the provider request so the model knows how to
// terminate the session.
func (a *Agent) allToolDecls() []provider.ToolDecl {
	var out []provider.ToolDecl
	if a.opts.Tools != nil {
		out = append(out, a.opts.Tools.Decls()...)
	}
	out = append(out, controlToolDecls()...)
	return out
}

func controlToolDecls() []provider.ToolDecl {
	return []provider.ToolDecl{
		{
			Name:        "add_finding",
			Description: "Append one security finding to the current report. Call once per distinct issue.",
			Schema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"severity":    map[string]any{"type": "string", "enum": []string{"critical", "high", "medium", "low", "info"}},
					"rule_id":     map[string]any{"type": "string", "description": "Short stable identifier (e.g. CWE-798, semgrep rule id)."},
					"file":        map[string]any{"type": "string"},
					"line":        map[string]any{"type": "integer"},
					"snippet":     map[string]any{"type": "string", "description": "The minimal code excerpt that contains the issue."},
					"title":       map[string]any{"type": "string"},
					"description": map[string]any{"type": "string"},
					"remediation": map[string]any{"type": "string"},
				},
				"required": []string{"severity", "rule_id", "snippet"},
			},
		},
		{
			Name:        "finalize_report",
			Description: "Terminate the review and emit the final report. Call exactly once when the review is complete.",
			Schema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"summary": map[string]any{"type": "string"},
				},
				"required": []string{"summary"},
			},
		},
	}
}

// buildFinalizeAck renders the human-readable acknowledgment for a
// finalize_report tool call. Includes the report file path (when written),
// the agent's own summary, severity counts, and a capped list of finding
// titles so the user has immediate inline visibility without opening the
// markdown.
func buildFinalizeAck(rep *report.Report, path string) string {
	var b strings.Builder
	if path != "" {
		fmt.Fprintf(&b, "✓ Report saved to %s\n", path)
	} else {
		b.WriteString("✓ Report finalized (no file written — reports writer not configured)\n")
	}
	if rep.Summary != "" {
		fmt.Fprintf(&b, "Summary: %s\n", rep.Summary)
	}
	fmt.Fprintf(&b, "Findings: %d total", len(rep.Findings))
	if c := severityCounts(rep.Findings); c != "" {
		fmt.Fprintf(&b, " (%s)", c)
	}
	b.WriteByte('\n')

	const maxList = 10
	for i, f := range rep.Findings {
		if i == maxList {
			fmt.Fprintf(&b, "  …and %d more (see the full markdown for details)\n", len(rep.Findings)-maxList)
			break
		}
		loc := f.File
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.File, f.Line)
		}
		title := f.Title
		if title == "" {
			title = f.RuleID
		}
		fmt.Fprintf(&b, "  • [%s] %s — %s\n", strings.ToUpper(f.Severity), title, loc)
	}
	return strings.TrimRight(b.String(), "\n")
}

// severityCounts returns "3 high, 5 medium" style summary, empty if no findings.
func severityCounts(findings []report.Finding) string {
	counts := map[string]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	order := []string{"critical", "high", "medium", "low", "info"}
	var parts []string
	for _, sev := range order {
		if n := counts[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, sev))
		}
	}
	return strings.Join(parts, ", ")
}

// composeSystemPrompt builds the full system instruction by stacking:
//  1. SOUL — identity (always-load, slow-moving facts about who/what)
//  2. MEMORY — session continuity (preferences, accepted FPs, recent decisions)
//
// Both are optional. If neither is set the system instruction is empty and
// the agent runs unstyled — useful for tests and for the bootstrap interview
// before SOUL.md exists.
func (a *Agent) composeSystemPrompt() string {
	soulPart := a.opts.Soul.SystemPrompt()
	memPart := strings.TrimSpace(a.opts.Memory)
	if memPart == "" {
		return soulPart
	}
	if soulPart == "" {
		return "# Memory — what you remember from prior sessions\n" + memPart
	}
	return soulPart + "\n\n# Memory — what you remember from prior sessions\n" + memPart
}

func (a *Agent) audit(evtType string, data map[string]any) error {
	if a.opts.Audit == nil {
		return nil
	}
	return a.opts.Audit.Log(audit.Event{Type: evtType, Data: data})
}

// persistMessage records the message to the conversation log (if configured)
// and notifies the OnMessage listener (if configured). The two are independent
// concerns: persistence is forensic, notification is for live UIs.
//
// Errors from the writer are intentionally swallowed: a flaky disk write
// should not abort the agent run mid-conversation. They surface as gaps in
// the log, not as fatal failures.
func (a *Agent) persistMessage(m provider.Message) {
	if a.opts.Conversation != nil {
		_ = a.opts.Conversation.Append(conversation.Record{Message: m})
	}
	if a.opts.OnMessage != nil {
		a.opts.OnMessage(m)
	}
}
