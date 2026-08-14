// Package memory implements the memory-curator subagent.
//
// At the end of a review session, the main agent is done but the conversation
// log on disk holds the *process* — what was looked at, what was decided, why
// a finding was filed or skipped. Some of that is worth keeping across
// sessions; most of it isn't. The curator's job is to read the transcript
// and decide what to append to MEMORY.md.
//
// Pedagogically this is the first concrete subagent in Argus. Its
// implementation is deliberately minimal: it re-uses the main agent loop
// (agent.Agent) with curator-specific Options. The only loop primitive added
// is `update_memory`, a tool the curator calls with the curated text. The
// loop terminates via the standard `finalize_report` exit, with a nil Reports
// writer so no file is emitted. This same pattern will scale to the generic
// `spawn_agent` tool in v0.3.
package memory

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/argusappsec/argus/pkg/agent"
	"github.com/argusappsec/argus/pkg/conversation"
	"github.com/argusappsec/argus/pkg/provider"
	"github.com/argusappsec/argus/pkg/soul"
	"github.com/argusappsec/argus/pkg/tool"
)

// Options bundles the curator's dependencies.
type Options struct {
	ConversationPath string

	// Store is the mechanism MEMORY is written through — the same one the
	// save_memory / mark_false_positive Tools use (ADR 0023). The curator is
	// handed it rather than a path because it is one of two callers of one
	// write, not the owner of a memory of its own: it shares the writers' lock
	// and meets the same size ceiling.
	Store *Store

	Provider provider.Provider

	// MaxTurns optionally caps the curator's loop. Default: 5.
	// The curator typically needs 2 turns (update_memory + finalize_report);
	// the cap is a safety net against runaway behavior.
	MaxTurns int
}

// Curate runs the memory-curator subagent. It reads the conversation at
// opts.ConversationPath, hands it to the LLM, and applies any update_memory
// calls through opts.Store.
//
// The whole run holds the Store's writers' lock: the curator reads the current
// MEMORY into its prompt, thinks for as long as an LLM call takes, and then
// rewrites the whole file, so a save_memory that landed in between would be
// erased by that rewrite.
func Curate(ctx context.Context, opts Options) error {
	if opts.Provider == nil {
		return errors.New("memory.Curate: provider required")
	}
	if opts.ConversationPath == "" || opts.Store == nil {
		return errors.New("memory.Curate: conversation path and memory store required")
	}

	records, err := conversation.ReadAll(opts.ConversationPath)
	if err != nil {
		return fmt.Errorf("memory.Curate: read conversation: %w", err)
	}
	if len(records) == 0 {
		return fmt.Errorf("memory.Curate: conversation %s is empty, nothing to curate", opts.ConversationPath)
	}

	defer opts.Store.hold()()

	existing, err := opts.Store.load()
	if err != nil {
		return fmt.Errorf("memory.Curate: read existing memory: %w", err)
	}

	transcript := renderTranscript(records)

	reg := tool.NewRegistry()
	reg.Register(newUpdateMemoryTool(opts.Store))

	curatorSoul := &soul.Soul{
		Persona: curatorPersona(existing),
	}

	maxTurns := opts.MaxTurns
	if maxTurns == 0 {
		maxTurns = 5
	}

	ag := agent.New(agent.Options{
		Provider: opts.Provider,
		Tools:    reg,
		Soul:     curatorSoul,
		MaxTurns: maxTurns,
		SeedMessages: []provider.Message{{
			Role:    "user",
			Content: transcript,
		}},
		// Reports, Conversation, Audit deliberately omitted: the curator
		// is ephemeral, leaves no report file, and its own log isn't
		// persisted (this is meta-work, not user-facing).
	})

	if _, err := ag.Run(ctx, agent.Target{}); err != nil {
		return fmt.Errorf("memory.Curate: agent run: %w", err)
	}
	return nil
}

// curatorPersona builds the curator's system prompt, including the current
// MEMORY.md so the LLM can decide what is already remembered vs new.
func curatorPersona(existing string) string {
	var b strings.Builder
	b.WriteString("You are the **memory curator** for an Argus security agent.\n\n")
	b.WriteString("You will receive the transcript of a security review session that just ended. ")
	b.WriteString("Your job is to extract a SHORT list of facts worth remembering across sessions — things that future runs of the agent (or its operators) would benefit from knowing. Examples:\n")
	b.WriteString("- User-level preferences (e.g. \"this user always wants HIGH findings flagged in a specific format\").\n")
	b.WriteString("- Confirmed false positives (e.g. \"rule X-001 always fires on test files, ignore there\").\n")
	b.WriteString("- Stable facts about the codebase (e.g. \"this repo uses Vault for secrets, so hardcoded-secret regex hits in config templates are placeholders\").\n")
	b.WriteString("- Decisions the operator made that would be tedious to re-derive.\n\n")
	b.WriteString("AVOID:\n")
	b.WriteString("- Restating the current report's findings (they live in their own file).\n")
	b.WriteString("- Ephemeral details (timestamps, exact commit SHAs).\n")
	b.WriteString("- Anything obvious from the codebase itself.\n\n")
	b.WriteString("Workflow:\n")
	b.WriteString("1. Read the transcript carefully.\n")
	b.WriteString("2. Call `update_memory(content)` with the FULL updated MEMORY.md content. ")
	b.WriteString("Preserve relevant existing memory; add the new facts; rewrite as a clean bulleted Markdown.\n")
	b.WriteString("3. Call `finalize_report(summary)` to end.\n\n")
	if existing != "" {
		b.WriteString("Current MEMORY.md content:\n```\n")
		b.WriteString(existing)
		b.WriteString("\n```\n")
	} else {
		b.WriteString("MEMORY.md is currently empty.\n")
	}
	return b.String()
}

// renderTranscript flattens conversation Records into a single human-readable
// block that the curator can reason over.
func renderTranscript(records []conversation.Record) string {
	var b strings.Builder
	b.WriteString("Here is the transcript of the session to curate:\n\n")
	for i, r := range records {
		fmt.Fprintf(&b, "--- turn %d (%s) ---\n", i+1, r.Message.Role)
		if r.Message.Content != "" {
			b.WriteString(r.Message.Content)
			b.WriteByte('\n')
		}
		for _, tc := range r.Message.ToolCalls {
			fmt.Fprintf(&b, "[tool call] %s(%v)\n", tc.Name, tc.Args)
		}
		for _, tr := range r.Message.ToolResults {
			fmt.Fprintf(&b, "[tool result %s] %s\n", tr.Name, truncate(tr.Output, 500))
		}
		b.WriteByte('\n')
	}
	return b.String()
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "... [truncated]"
}

// newUpdateMemoryTool returns the curator-private `update_memory` tool. It is
// the curator's shape of the one write: the whole file, replaced.
func newUpdateMemoryTool(store *Store) tool.Tool {
	return &updateMemory{store: store}
}

type updateMemory struct{ store *Store }

func (u *updateMemory) Name() string { return "update_memory" }

func (u *updateMemory) Description() string {
	return "Replace MEMORY.md with the supplied content. Call once with the FULL final content — not a diff. " +
		"Preserve relevant existing memory and add the new facts you decided are worth keeping."
}

func (u *updateMemory) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"content": map[string]any{
				"type":        "string",
				"description": "The full new content of MEMORY.md as Markdown.",
			},
		},
		"required": []string{"content"},
	}
}

// Execute replaces MEMORY through the Store, whose lock Curate is already
// holding for this run — hence the unlocked internal rather than the method.
// The curator is told when it has left MEMORY full, on the same terms the
// external AI is, and can act on it in the turn it has left.
func (u *updateMemory) Execute(_ context.Context, args map[string]any) (string, error) {
	content, _ := args["content"].(string)
	if content == "" {
		return "", errors.New("update_memory: content required")
	}
	w, err := u.store.replace(content)
	if err != nil {
		return "", err
	}
	return join("ok", w.Signal()), nil
}
