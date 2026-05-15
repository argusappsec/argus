package tool

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
)

// NewListFiles returns a list_files tool rooted at root. All paths returned
// or accepted are relative to root; absolute or escaping paths are refused.
func NewListFiles(root string) Tool { return &listFiles{root: root} }

type listFiles struct{ root string }

func (l *listFiles) Name() string { return "list_files" }

func (l *listFiles) Description() string {
	return "List files in the repository under an optional sub-path. Returns one path per line, relative to the repository root."
}

func (l *listFiles) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"path": map[string]any{
				"type":        "string",
				"description": "Sub-path relative to the repository root. Empty means root.",
			},
		},
	}
}

func (l *listFiles) Execute(_ context.Context, args map[string]any) (string, error) {
	sub, _ := args["path"].(string)
	abs, err := resolveWithinRoot(l.root, sub)
	if err != nil {
		return "", err
	}
	var paths []string
	if err := filepath.WalkDir(abs, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			// Skip noisy/conventional directories at any depth.
			name := d.Name()
			if name == ".git" || name == "node_modules" || name == "vendor" {
				return fs.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(l.root, p)
		if err != nil {
			return err
		}
		paths = append(paths, filepath.ToSlash(rel))
		return nil
	}); err != nil {
		return "", fmt.Errorf("list_files: %w", err)
	}
	sort.Strings(paths)
	return strings.Join(paths, "\n"), nil
}

// resolveWithinRoot joins sub to root and refuses results outside root.
// Empty sub is allowed and resolves to root itself.
func resolveWithinRoot(root, sub string) (string, error) {
	if filepath.IsAbs(sub) {
		return "", errors.New("absolute paths not allowed")
	}
	clean := filepath.Clean(filepath.Join(root, sub))
	rootClean := filepath.Clean(root)
	if clean != rootClean && !strings.HasPrefix(clean, rootClean+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes repository root: %q", sub)
	}
	return clean, nil
}
