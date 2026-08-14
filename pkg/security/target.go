package security

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/argusappsec/argus/pkg/session"
)

// scanTarget resolves the directory a scanner runs against. Two callers, one
// rule.
//
// Argus's own agent loop pins the target on the Session when a review starts
// and passes no path, so an omitted `path` keeps meaning "whatever is under
// review". An external AI driving the Toolbox surface has no review to inherit
// from, so it names the directory itself: an absolute path on the Argus host,
// which is where the code is under ADR 0024's same-machine constraint.
//
// Where a review has pinned a root, the named path must be inside it. A scanner
// is a file-scoped Tool like the rest and stays sandboxed to the tree under
// review — otherwise the argument would be a way for content inside a reviewed
// repository to talk the model into scanning the rest of the daemon's disk. The
// Toolbox surface has no pinned root, which is precisely why it may name one.
//
// Only the caller's path is validated. A Session root is a checkout Argus made
// itself; a path in a tool call is somebody's word for one, and a scan that
// silently found nothing because it ran against a directory that is not there
// is the worst answer available — so a target Argus cannot scan is refused by
// naming the problem.
func scanTarget(s *session.Session, args map[string]any) (string, error) {
	root := s.Root()
	path, _ := args["path"].(string)
	path = strings.TrimSpace(path)
	if path == "" {
		if root == "" {
			return "", errors.New("no target to scan: pass `path` as an absolute path to a directory on the machine " +
				"Argus runs on — it scans code it can already see locally. During a review the target is inherited " +
				"and `path` may be omitted")
		}
		return root, nil
	}

	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("target %q is not an absolute path: the scan runs on the Argus host, "+
			"so name the directory from the filesystem root", path)
	}
	if root != "" && !within(root, path) {
		return "", fmt.Errorf("target %q is outside the tree under review (%s): a review scans the checkout it was "+
			"started on, so name a directory inside it or omit `path` to scan all of it", path, root)
	}
	info, err := os.Stat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "", fmt.Errorf("target %q does not exist on the Argus host", path)
	case err != nil:
		return "", fmt.Errorf("target %q is not readable on the Argus host: %w", path, err)
	case !info.IsDir():
		return "", fmt.Errorf("target %q is not a directory: the scanners run over a tree, "+
			"so name the directory that holds the file", path)
	}
	// Stat only proves the directory is there. Opening it is what proves Argus
	// may list it, and finding that out here beats finding it out as a scanner's
	// empty report.
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("target %q is not readable by the user Argus runs as: %w", path, err)
	}
	_ = f.Close()
	return path, nil
}

// within reports whether path is root itself or lies under it. Same rule the
// file-scoped Tools resolve their arguments by, stated over two absolute paths.
func within(root, path string) bool {
	root = filepath.Clean(root)
	path = filepath.Clean(path)
	return path == root || strings.HasPrefix(path, root+string(filepath.Separator))
}

// targetSchemaProperty is the `path` argument every scanner takes, described
// once so the three read identically to the AI that calls them.
func targetSchemaProperty() map[string]any {
	return map[string]any{
		"type": "string",
		"description": "Absolute path of the directory to scan, on the machine Argus runs on. " +
			"Omit it during a review to scan the whole checkout under review; a path named during a " +
			"review must be inside that checkout.",
	}
}
