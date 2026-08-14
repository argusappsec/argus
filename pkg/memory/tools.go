package memory

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/argusappsec/argus/pkg/tool"
)

// save_memory and mark_false_positive are the deterministic half of "one
// mechanism, two callers" (ADR 0023): ordinary Tools over the Store, admitted
// onto the MCP surface so a Provider-less Argus still remembers. Their
// descriptions are what an external AI reads to decide whether to reach for
// them, so they say what remembering costs and where the alternative is.

// NewSaveMemory returns the save_memory Tool: one durable fact appended to
// MEMORY through the shared mechanism.
func NewSaveMemory(store *Store) tool.Tool { return &saveMemory{store: store} }

type saveMemory struct{ store *Store }

func (t *saveMemory) Name() string { return "save_memory" }

func (t *saveMemory) Description() string {
	return "Remember one thing across sessions. Argus loads MEMORY into every future conversation, so what you " +
		"save here travels forward to the next session — a preference the developer stated, a convention this " +
		"team follows, a decision that would be tedious to work out again. Call it when something was settled " +
		"that should not have to be settled twice. Keep each entry to a sentence or two: MEMORY is paid for on " +
		"every call, so background knowledge, anything long, and anything you would want to look up rather than " +
		"be reminded of belongs in a CONTEXT document (write_context) instead. Nothing is overwritten — the " +
		"entry is appended to what Argus already remembers."
}

func (t *saveMemory) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"content": map[string]any{
				"type":        "string",
				"description": "The fact, preference or decision to remember, in one or two sentences.",
			},
		},
		"required": []string{"content"},
	}
}

func (t *saveMemory) Execute(_ context.Context, args map[string]any) (string, error) {
	content, _ := args["content"].(string)
	if strings.TrimSpace(content) == "" {
		return "", errors.New("save_memory: content required")
	}
	w, err := t.store.Append(content)
	if err != nil {
		return "", err
	}
	return join("Saved to MEMORY; Argus will have it in every future conversation.", w.Signal()), nil
}

// NewMarkFalsePositive returns the mark_false_positive Tool: an accepted false
// positive recorded in MEMORY as advisory context.
func NewMarkFalsePositive(store *Store) tool.Tool { return &markFalsePositive{store: store} }

type markFalsePositive struct{ store *Store }

func (t *markFalsePositive) Name() string { return "mark_false_positive" }

func (t *markFalsePositive) Description() string {
	return "Record that a security finding was judged a false positive here, so the developer is not shown the " +
		"same wrong result forever and whoever looks next knows it was already considered. What is recorded is " +
		"ADVISORY, not a mute: future reviews read it as context and re-judge the same pattern per situation, so " +
		"the same finding in a genuinely vulnerable place elsewhere can still be flagged. Give the reason — it is " +
		"what makes the record re-judgeable rather than a rule nobody can revisit."
}

func (t *markFalsePositive) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"rule_id": map[string]any{
				"type":        "string",
				"description": "The rule or check that fired, e.g. CWE-89 or the scanner's rule id.",
			},
			"file": map[string]any{
				"type":        "string",
				"description": "Optional path the finding was reported at, to say where the judgement was made.",
			},
			"reason": map[string]any{
				"type":        "string",
				"description": "Why it is a false positive here. Recorded so a future review can re-judge it in context.",
			},
		},
		"required": []string{"rule_id"},
	}
}

func (t *markFalsePositive) Execute(_ context.Context, args map[string]any) (string, error) {
	ruleID, _ := args["rule_id"].(string)
	if strings.TrimSpace(ruleID) == "" {
		return "", errors.New("mark_false_positive: rule_id required")
	}
	file, _ := args["file"].(string)
	reason, _ := args["reason"].(string)

	w, err := t.store.Append(advisory(ruleID, file, reason))
	if err != nil {
		return "", err
	}
	return join(fmt.Sprintf(
		"Recorded in MEMORY: finding %q%s was accepted as a false positive. It is advisory — future reviews "+
			"re-judge the same pattern in context, so this is not a global mute.", ruleID, at(file)),
		w.Signal()), nil
}

// advisory renders an accepted false positive as the line MEMORY carries. The
// wording is load-bearing: it is read back into a system prompt, and what it has
// to convey there is that this is guidance to weigh, not a rule that drops a
// finding. A content-stable match is not sufficient grounds to silently discard
// a result somewhere else.
func advisory(ruleID, file, reason string) string {
	line := fmt.Sprintf(
		"Advisory (false positive accepted): finding `%s`%s was judged a false positive. Treat as guidance only — "+
			"re-judge the same pattern per context in future reviews; this is NOT a global mute.", ruleID, at(file))
	if reason = strings.TrimSpace(reason); reason != "" {
		line += " Reason: " + reason
	}
	return line
}

// at renders the optional location of a finding.
func at(file string) string {
	if strings.TrimSpace(file) == "" {
		return ""
	}
	return " at `" + file + "`"
}

// join appends the Store's signal to a confirmation when there is one, so a
// caller reads one message rather than two fields.
func join(confirmation, signal string) string {
	if signal == "" {
		return confirmation
	}
	return confirmation + " " + signal
}
