package tool

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"

	"github.com/redcarbon-dev/argus/pkg/session"
)

// NewListFiles returns a list_files tool that reads its target directory from
// the supplied Session at every Execute. The Session's root may change
// mid-conversation (e.g. after a start_review_* tool call); the same tool
// instance will simply see the new target on the next invocation.
func NewListFiles(s *session.Session) Tool { return &listFiles{sess: s} }

type listFiles struct{ sess *session.Session }

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
	root := l.sess.Root()
	if root == "" {
		return "", errors.New("no target set: call start_review_local or start_review_github first")
	}
	sub, _ := args["path"].(string)
	abs, err := resolveWithinRoot(root, sub)
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
		rel, err := filepath.Rel(root, p)
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
