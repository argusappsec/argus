package tool_test

import (
	"context"
	"strings"
	"testing"

	"github.com/redcarbon-dev/argus/pkg/session"
	"github.com/redcarbon-dev/argus/pkg/tool"
)

// fakeRecorder is a session.MissRecorder that records the paths the tools reach
// for but the (empty) workspace does not hold.
type fakeRecorder struct {
	present map[string]bool
	missed  []string
}

func (f *fakeRecorder) Has(p string) bool { return f.present[p] }
func (f *fakeRecorder) RecordMiss(p string) {
	f.missed = append(f.missed, p)
}

// In a Snapshot review (a miss recorder is set) a read of an absent path is a
// collaboration step, not an error: the path is recorded and the agent gets a
// note so it keeps reviewing.
func TestReadFile_RecordsMissInSnapshotReview(t *testing.T) {
	root := t.TempDir() // an empty workspace: the file is genuinely absent
	sess := session.New()
	sess.SetRoot(root)
	rec := &fakeRecorder{present: map[string]bool{}}
	sess.SetMissRecorder(rec)

	out, err := tool.NewReadFile(sess).Execute(context.Background(), map[string]any{"path": "internal/auth/middleware.go"})
	if err != nil {
		t.Fatalf("read of an absent path in a Snapshot review must not error: %v", err)
	}
	if !strings.Contains(out, "internal/auth/middleware.go") || !strings.Contains(out, "not in this snapshot") {
		t.Errorf("note did not explain the miss: %q", out)
	}
	if len(rec.missed) != 1 || rec.missed[0] != "internal/auth/middleware.go" {
		t.Errorf("recorded misses = %v, want [internal/auth/middleware.go]", rec.missed)
	}
}

// Without a miss recorder (a repo/PR review) a read of an absent path stays a
// hard error — the collaboration behavior is scoped to Snapshot reviews.
func TestReadFile_AbsentPathStillErrorsWithoutRecorder(t *testing.T) {
	sess := session.New()
	sess.SetRoot(t.TempDir())

	if _, err := tool.NewReadFile(sess).Execute(context.Background(), map[string]any{"path": "nope.go"}); err == nil {
		t.Error("read of an absent path must error when no miss recorder is set")
	}
}

// list_files of an absent sub-path in a Snapshot review is a note, not an error
// — and crucially NOT a recorded miss: a directory is not a suppliable file, so
// it must not pollute files_needed.
func TestListFiles_AbsentSubPathIsNoteNotMiss(t *testing.T) {
	sess := session.New()
	sess.SetRoot(t.TempDir())
	rec := &fakeRecorder{present: map[string]bool{}}
	sess.SetMissRecorder(rec)

	out, err := tool.NewListFiles(sess).Execute(context.Background(), map[string]any{"path": "internal/payments"})
	if err != nil {
		t.Fatalf("list of an absent sub-path in a Snapshot review must not error: %v", err)
	}
	if !strings.Contains(out, "internal/payments") {
		t.Errorf("note did not name the missing sub-path: %q", out)
	}
	if len(rec.missed) != 0 {
		t.Errorf("a directory must not be recorded as a needed file, got %v", rec.missed)
	}
}
