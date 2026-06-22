package tool_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/redcarbon-dev/argus/pkg/codehost"
	"github.com/redcarbon-dev/argus/pkg/session"
	"github.com/redcarbon-dev/argus/pkg/tool"
)

func TestPRDiff_ReturnsChangedFilesAndHunks(t *testing.T) {
	sess := session.New()
	sess.SetPRDiff(codehost.PRDiff{Files: []codehost.ChangedFile{{
		Path:   "config.py",
		Status: "modified",
		Patch:  "@@ -40,3 +40,5 @@\n+new",
		Hunks:  []codehost.Hunk{{NewStart: 40, NewLines: 5}},
	}}})

	out, err := tool.NewPRDiff(sess).Execute(context.Background(), nil)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}

	var got struct {
		Files []struct {
			Path   string `json:"path"`
			Status string `json:"status"`
			Hunks  []struct {
				NewStart int `json:"new_start"`
				NewLines int `json:"new_lines"`
			} `json:"hunks"`
		} `json:"files"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("unmarshal output: %v\n%s", err, out)
	}
	if len(got.Files) != 1 || got.Files[0].Path != "config.py" || got.Files[0].Status != "modified" {
		t.Fatalf("files = %+v", got.Files)
	}
	if len(got.Files[0].Hunks) != 1 || got.Files[0].Hunks[0].NewStart != 40 || got.Files[0].Hunks[0].NewLines != 5 {
		t.Errorf("hunks = %+v, want {40,5}", got.Files[0].Hunks)
	}
}

func TestPRDiff_NoDiffOutsidePRReview(t *testing.T) {
	// A plain `argus review` never sets a diff; the tool says so rather than
	// pretending the whole tree is in scope.
	out, err := tool.NewPRDiff(session.New()).Execute(context.Background(), nil)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(out, "not a pull-request review") {
		t.Errorf("output = %q, want a not-a-PR-review notice", out)
	}
}
