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

	if err := a.audit("session_start", map[string]any{"repo": t.Repo, "sha": t.SHA}); err != nil {
		return nil, err
	}

	var msgs []provider.Message
	if len(a.opts.SeedMessages) > 0 {
		msgs = append(msgs, a.opts.SeedMessages...)
	} else {
		msgs = append(msgs, provider.Message{
			Role:    "user",
			Content: fmt.Sprintf("Review %s at %s.", t.Repo, t.SHA),
		})
	}
	for _, m := range msgs {
		a.persistMessage(m)
	}

	decls := a.allToolDecls()
	system := a.opts.Soul.SystemPrompt()

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
				if a.opts.Reports != nil {
					path, err := a.opts.Reports.Write(*rep)
					if err != nil {
						return nil, fmt.Errorf("write report: %w", err)
					}
					_ = a.audit("session_end", map[string]any{"report_path": path, "findings": len(rep.Findings)})
				} else {
					_ = a.audit("session_end", map[string]any{"findings": len(rep.Findings)})
				}
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
