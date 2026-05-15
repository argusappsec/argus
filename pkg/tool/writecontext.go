package tool

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// NewWriteContext returns a `write_context` tool that persists agent-acquired
// knowledge into ~/.argus/context/<name>.md. It is the counterpart of
// read_context / list_context: how new knowledge enters the on-demand
// knowledge base.
//
// Typical use during a chat:
//
//	user > "auth-service uses Vault; ${VAULT_*} in manifests are placeholders"
//	agent > write_context("auth-conventions", "Auth service uses Vault. ...")
//	agent > "Got it, saved."
//
// Subsequent reviews discover this knowledge via list_context() and pull
// the relevant doc via read_context(name).
func NewWriteContext(dir string) Tool { return &writeContext{dir: dir} }

type writeContext struct{ dir string }

func (w *writeContext) Name() string { return "write_context" }

func (w *writeContext) Description() string {
	return "Persist a piece of background knowledge about the company / codebase " +
		"to the context library so it is available in future sessions. Use this when " +
		"the user shares stable facts (architecture, conventions, accepted false " +
		"positives, integrations) that should inform future reviews. " +
		"Replaces any existing document with the same name — pass the FULL new " +
		"content, not a diff. Pair with list_context / read_context to discover and " +
		"read what is already on file before overwriting."
}

func (w *writeContext) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"name": map[string]any{
				"type":        "string",
				"description": "Document name (without path separators). The .md extension is optional. Examples: architecture, threat-model, auth-conventions, known-fps.",
			},
			"content": map[string]any{
				"type":        "string",
				"description": "Full markdown body to write. Replaces any existing content with the same name.",
			},
		},
		"required": []string{"name", "content"},
	}
}

func (w *writeContext) Execute(_ context.Context, args map[string]any) (string, error) {
	name, _ := args["name"].(string)
	content, _ := args["content"].(string)
	if name == "" {
		return "", errors.New("write_context: name required")
	}
	if content == "" {
		return "", errors.New("write_context: content required")
	}
	if strings.ContainsAny(name, "/\\") || strings.Contains(name, "..") || filepath.IsAbs(name) {
		return "", fmt.Errorf("write_context: invalid name %q: path separators, parent references and absolute paths are not allowed", name)
	}
	if !strings.HasSuffix(name, ".md") {
		name += ".md"
	}

	if err := os.MkdirAll(w.dir, 0o700); err != nil {
		return "", fmt.Errorf("write_context: mkdir: %w", err)
	}
	path := filepath.Join(w.dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return "", fmt.Errorf("write_context: write: %w", err)
	}
	return fmt.Sprintf("Context document saved to %s.", path), nil
}
