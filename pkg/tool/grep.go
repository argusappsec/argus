package tool

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/argusappsec/argus/pkg/session"
)

// NewGrep returns a grep tool that searches files under the Session's current
// root for a regex.
func NewGrep(s *session.Session) Tool { return &grep{sess: s} }

type grep struct{ sess *session.Session }

func (g *grep) Name() string { return "grep" }

func (g *grep) Description() string {
	return "Search the repository for lines matching a regular expression. Output is `path:line:match` per result."
}

func (g *grep) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"pattern": map[string]any{"type": "string", "description": "Go regular expression."},
			"path":    map[string]any{"type": "string", "description": "Optional sub-path under repository root."},
		},
		"required": []string{"pattern"},
	}
}

func (g *grep) Execute(_ context.Context, args map[string]any) (string, error) {
	root := g.sess.Root()
	if root == "" {
		return "", errors.New("no target set: call start_review_local or start_review_github first")
	}
	pattern, _ := args["pattern"].(string)
	if pattern == "" {
		return "", fmt.Errorf("grep: pattern required")
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return "", fmt.Errorf("grep: invalid pattern: %w", err)
	}
	sub, _ := args["path"].(string)
	start, err := resolveWithinRoot(root, sub)
	if err != nil {
		return "", err
	}

	var hits []string
	walkErr := filepath.WalkDir(start, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == "node_modules" || name == "vendor" {
				return fs.SkipDir
			}
			return nil
		}
		f, err := os.Open(p)
		if err != nil {
			return nil // skip unreadable files silently
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		line := 0
		for sc.Scan() {
			line++
			if re.MatchString(sc.Text()) {
				hits = append(hits, fmt.Sprintf("%s:%d:%s", rel, line, strings.TrimSpace(sc.Text())))
			}
		}
		f.Close()
		return nil
	})
	if walkErr != nil {
		return "", fmt.Errorf("grep: %w", walkErr)
	}
	sort.Strings(hits)
	return strings.Join(hits, "\n"), nil
}
