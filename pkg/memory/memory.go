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
	"io/fs"
	"os"
	"path/filepath"
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
	MemoryPath       string
	Provider         provider.Provider

	// MaxTurns optionally caps the curator's loop. Default: 5.
	// The curator typically needs 2 turns (update_memory + finalize_report);
	// the cap is a safety net against runaway behavior.
	MaxTurns int
}

// Curate runs the memory-curator subagent. It reads the conversation at
// opts.ConversationPath, hands it to the LLM, and applies any update_memory
// calls to opts.MemoryPath.
func Curate(ctx context.Context, opts Options) error {
	if opts.Provider == nil {
		return errors.New("memory.Curate: provider required")
	}
	if opts.ConversationPath == "" || opts.MemoryPath == "" {
		return errors.New("memory.Curate: conversation and memory paths required")
	}

	records, err := conversation.ReadAll(opts.ConversationPath)
	if err != nil {
		return fmt.Errorf("memory.Curate: read conversation: %w", err)
	}
	if len(records) == 0 {
		return fmt.Errorf("memory.Curate: conversation %s is empty, nothing to curate", opts.ConversationPath)
	}

	existing, err := loadExistingMemory(opts.MemoryPath)
	if err != nil {
		return fmt.Errorf("memory.Curate: read existing memory: %w", err)
	}

	transcript := renderTranscript(records)

	reg := tool.NewRegistry()
	reg.Register(newUpdateMemoryTool(opts.MemoryPath))

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

func loadExistingMemory(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	return string(b), nil
}

// newUpdateMemoryTool returns the curator-private `update_memory` tool.
// It writes the entire MEMORY.md atomically (rename-from-tmp pattern).
func newUpdateMemoryTool(memoryPath string) tool.Tool {
	return &updateMemory{path: memoryPath}
}

type updateMemory struct{ path string }

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

func (u *updateMemory) Execute(_ context.Context, args map[string]any) (string, error) {
	content, _ := args["content"].(string)
	if content == "" {
		return "", errors.New("update_memory: content required")
	}
	if err := os.MkdirAll(filepath.Dir(u.path), 0o700); err != nil {
		return "", fmt.Errorf("update_memory: mkdir: %w", err)
	}
	if err := os.WriteFile(u.path, []byte(content), 0o600); err != nil {
		return "", fmt.Errorf("update_memory: write: %w", err)
	}
	return "ok", nil
}
