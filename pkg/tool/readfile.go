package tool

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/argusappsec/argus/pkg/session"
)

// NewReadFile returns a read_file tool that resolves paths against the
// Session's current root at every invocation.
func NewReadFile(s *session.Session) Tool { return &readFile{sess: s} }

type readFile struct{ sess *session.Session }

func (r *readFile) Name() string { return "read_file" }

func (r *readFile) Description() string {
	return "Read a file from the repository, optionally restricted to a line range. Line numbers are 1-indexed and inclusive."
}

func (r *readFile) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"path":       map[string]any{"type": "string", "description": "Path relative to repository root."},
			"line_start": map[string]any{"type": "integer", "description": "1-indexed first line to return."},
			"line_end":   map[string]any{"type": "integer", "description": "1-indexed last line (inclusive)."},
		},
		"required": []string{"path"},
	}
}

func (r *readFile) Execute(_ context.Context, args map[string]any) (string, error) {
	root := r.sess.Root()
	if root == "" {
		return "", errors.New("no target set: call start_review_local or start_review_github first")
	}
	path, _ := args["path"].(string)
	if path == "" {
		return "", fmt.Errorf("read_file: path required")
	}
	abs, err := resolveWithinRoot(root, path)
	if err != nil {
		return "", err
	}

	start := intArg(args["line_start"])
	end := intArg(args["line_end"])

	if start == 0 && end == 0 {
		b, err := os.ReadFile(abs)
		if err != nil {
			if miss, ok := r.recordMiss(path, err); ok {
				return miss, nil
			}
			return "", fmt.Errorf("read_file: %w", err)
		}
		return string(b), nil
	}

	f, err := os.Open(abs)
	if err != nil {
		if miss, ok := r.recordMiss(path, err); ok {
			return miss, nil
		}
		return "", fmt.Errorf("read_file: %w", err)
	}
	defer f.Close()

	var b strings.Builder
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	line := 0
	for sc.Scan() {
		line++
		if start > 0 && line < start {
			continue
		}
		if end > 0 && line > end {
			break
		}
		b.WriteString(sc.Text())
		b.WriteByte('\n')
	}
	if err := sc.Err(); err != nil {
		return "", fmt.Errorf("read_file: %w", err)
	}
	return b.String(), nil
}

// recordMiss turns a read of an absent path into a collaboration step rather
// than a hard error, but only in a Snapshot review (a miss recorder is set). The
// workspace records the path so it surfaces in the run's files_needed list, and
// the agent gets a note — not an error — so it keeps reviewing the files it has
// and can flag what it still needs. Returns ok=false (so the caller errors as
// usual) for non-Snapshot reviews or for any failure other than not-exist.
func (r *readFile) recordMiss(path string, err error) (string, bool) {
	rec := r.sess.MissRecorder()
	if rec == nil || !errors.Is(err, os.ErrNotExist) {
		return "", false
	}
	rec.RecordMiss(path)
	return fmt.Sprintf("%s is not in this snapshot — it was not among the files supplied for review. "+
		"It has been recorded as needed; continue reviewing the files you do have, and it will be "+
		"requested from the developer so you can finish the review with it.", path), true
}

func intArg(v any) int {
	switch x := v.(type) {
	case int:
		return x
	case float64:
		return int(x)
	}
	return 0
}
