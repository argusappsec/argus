package tool

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// NewListContext returns a `list_context` tool that lists *.md files in the
// agent's CONTEXT directory (typically ~/.argus/context/). Used by the agent
// to discover what background knowledge is available on demand, without
// paying token cost for content it doesn't need.
func NewListContext(dir string) Tool { return &listContext{dir: dir} }

type listContext struct{ dir string }

func (l *listContext) Name() string { return "list_context" }

func (l *listContext) Description() string {
	return "List the background knowledge documents available about the company/environment. " +
		"Returns one .md filename per line. " +
		"Call read_context(name) to fetch the body of a specific document when relevant to the task. " +
		"Documents typically cover: architecture, threat model, compliance requirements, known false positives, escalation policy."
}

func (l *listContext) Schema() map[string]any {
	return map[string]any{"type": "object", "properties": map[string]any{}}
}

func (l *listContext) Execute(_ context.Context, _ map[string]any) (string, error) {
	entries, err := os.ReadDir(l.dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", nil // missing dir = no context, not an error
		}
		return "", fmt.Errorf("list_context: %w", err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".md") {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, "\n"), nil
}

// NewReadContext returns a `read_context` tool that returns the body of one
// context document by name. The .md extension is optional in the argument.
func NewReadContext(dir string) Tool { return &readContext{dir: dir} }

type readContext struct{ dir string }

func (r *readContext) Name() string { return "read_context" }

func (r *readContext) Description() string {
	return "Read the body of one background knowledge document by name. " +
		"Use list_context first to discover available names. " +
		"The .md extension is optional in the argument."
}

func (r *readContext) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"name": map[string]any{
				"type":        "string",
				"description": "Document name, with or without the .md extension. Must not contain path separators.",
			},
		},
		"required": []string{"name"},
	}
}

func (r *readContext) Execute(_ context.Context, args map[string]any) (string, error) {
	name, _ := args["name"].(string)
	if name == "" {
		return "", errors.New("read_context: name required")
	}
	// Reject any traversal — context names are flat document handles, not paths.
	if strings.ContainsAny(name, "/\\") || strings.Contains(name, "..") {
		return "", fmt.Errorf("read_context: invalid name %q: path separators and parent references are not allowed", name)
	}
	if !strings.HasSuffix(name, ".md") {
		name += ".md"
	}

	path := filepath.Join(r.dir, name)
	// Defense in depth: confirm the resolved absolute path is still under dir.
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("read_context: %w", err)
	}
	absDir, err := filepath.Abs(r.dir)
	if err != nil {
		return "", fmt.Errorf("read_context: %w", err)
	}
	if !strings.HasPrefix(absPath, absDir+string(filepath.Separator)) {
		return "", fmt.Errorf("read_context: %q escapes context dir", name)
	}

	b, err := os.ReadFile(absPath)
	if err != nil {
		return "", fmt.Errorf("read_context: %w", err)
	}
	return string(b), nil
}
