package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/argusappsec/argus/pkg/deployment"
)

// Starting as a Toolbox is not a silent condition: the operator is told at
// startup, in the vocabulary the rest of the product uses, why Argus will not
// be reviewing anything on its own.
func TestShapeNotice_ToolboxNamesTheShapeAndItsConsequences(t *testing.T) {
	notice := strings.Join(shapeNotice(deployment.Toolbox), "\n")
	for _, want := range []string{"toolbox", "no LLM Provider", "review", "MCP", "argus init"} {
		if !strings.Contains(notice, want) {
			t.Errorf("notice does not mention %q:\n%s", want, notice)
		}
	}
}

func TestShapeNotice_ColleagueSaysSoInOneLine(t *testing.T) {
	notice := shapeNotice(deployment.Colleague)
	if len(notice) != 1 || !strings.Contains(notice[0], "colleague") {
		t.Errorf("colleague notice = %q, want one line naming the shape", notice)
	}
}

// The shape doctor reports is the daemon's own derivation, over the same
// inputs — including a fallback credential that lives in the daemon's .env
// rather than the shell.
func TestDeploymentShape_MatchesWhatTheDaemonWouldDerive(t *testing.T) {
	t.Setenv("GEMINI_API_KEY", "")
	home := t.TempDir()
	if got := deploymentShape(home); got != deployment.Toolbox {
		t.Errorf("empty home: shape = %v, want toolbox", got)
	}

	if err := os.WriteFile(filepath.Join(home, ".env"), []byte("GEMINI_API_KEY=gem-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := deploymentShape(home); got != deployment.Colleague {
		t.Errorf("fallback key in .env: shape = %v, want colleague", got)
	}
}
