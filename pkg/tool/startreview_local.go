package tool

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/redcarbon-dev/argus/pkg/session"
)

// NewStartReviewLocal returns a `start_review_local` tool that the LLM calls
// when the user asks to review code already present on disk. It validates the
// path, sets the Session's root, and reports back. File-scoped tools (list_files,
// read_file, grep, run_semgrep, ...) read from session.Root() and will see the
// new target on their next invocation.
//
// This tool does NOT clone anything: that's start_review_github's job.
func NewStartReviewLocal(s *session.Session) Tool {
	return &startReviewLocal{sess: s}
}

type startReviewLocal struct{ sess *session.Session }

func (t *startReviewLocal) Name() string { return "start_review_local" }

func (t *startReviewLocal) Description() string {
	return "Start a security review on a local directory already present on disk. " +
		"Use when the user provides a filesystem path (e.g. '/Users/.../my-project'). " +
		"For GitHub URLs use start_review_github instead. " +
		"After this tool succeeds, the file-scoped tools (list_files, read_file, grep, run_semgrep, run_gitleaks, run_osv_scanner) " +
		"will operate on the given path."
}

func (t *startReviewLocal) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"path": map[string]any{
				"type":        "string",
				"description": "Absolute filesystem path to the directory containing the code under review.",
			},
		},
		"required": []string{"path"},
	}
}

func (t *startReviewLocal) Execute(_ context.Context, args map[string]any) (string, error) {
	path, _ := args["path"].(string)
	if path == "" {
		return "", errors.New("start_review_local: path is required")
	}

	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("start_review_local: %w", err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("start_review_local: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("start_review_local: %q is not a directory", abs)
	}

	t.sess.SetRoot(abs)
	return fmt.Sprintf("Local review target set to %s. Proceed with list_files / read_file / grep / run_semgrep / run_gitleaks / run_osv_scanner.", abs), nil
}
