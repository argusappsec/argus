package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/argusappsec/argus/pkg/deployment"
	"github.com/argusappsec/argus/pkg/security"
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

// The startup log says what this host can scan with and what it cannot, and
// points at the catalog page that explains how to install each missing Tool —
// discovery happens once, so this is where the operator learns it.
func TestToolsNotice_ListsRegisteredAndMissingToolsWithCatalogLinks(t *testing.T) {
	d := security.Discover(func(name string) (string, error) {
		if name == "gitleaks" {
			return "/usr/local/bin/gitleaks", nil
		}
		return "", exec.ErrNotFound
	})

	notice := toolsNotice(d)
	text := strings.Join(notice, "\n")

	var registered, missing []string
	for _, line := range notice {
		if !strings.HasPrefix(line, "argusd:") {
			t.Errorf("startup line %q is not prefixed argusd:", line)
		}
		switch {
		case strings.Contains(line, "registered"):
			registered = append(registered, line)
		case strings.Contains(line, "/guide/scanners/"):
			missing = append(missing, line)
		}
	}
	if len(registered) != 1 || !strings.Contains(registered[0], "gitleaks") ||
		strings.Contains(registered[0], "sast") || strings.Contains(registered[0], "osv-scanner") {
		t.Errorf("want one line naming exactly the registered gitleaks:\n%s", text)
	}
	for _, want := range []string{"/guide/scanners/sast/", "/guide/scanners/osv-scanner/"} {
		if !strings.Contains(strings.Join(missing, "\n"), want) {
			t.Errorf("a missing Tool's line must link %s:\n%s", want, text)
		}
	}
	if strings.Contains(text, "/guide/scanners/gitleaks/") {
		t.Errorf("an installed Tool needs no install link:\n%s", text)
	}
}

// The SAST Tool runs one of two engines. The startup log says which one this
// host will run, so an operator who installed opengrep next to semgrep can
// see it took over.
func TestToolsNotice_NamesTheSASTEngineThatWillRun(t *testing.T) {
	d := security.Discover(func(name string) (string, error) {
		if name == "opengrep" || name == "semgrep" {
			return "/usr/local/bin/" + name, nil
		}
		return "", exec.ErrNotFound
	})

	registered := toolsNotice(d)[0]

	if !strings.Contains(registered, "sast (opengrep)") {
		t.Errorf("want the registered line to name the engine, sast (opengrep): %q", registered)
	}
}

// A Tool the operator switched off in argus.yaml is reported as disabled, on a
// line of its own — not as missing with an install link, which would send the
// operator to install something they deliberately turned off.
func TestToolsNotice_ReportsADisabledToolAsDisabledNotMissing(t *testing.T) {
	d := security.Discover(func(name string) (string, error) {
		if name == "gitleaks" {
			return "/usr/local/bin/gitleaks", nil
		}
		return "", exec.ErrNotFound
	}).Disable([]string{"gitleaks", "sast"})

	notice := toolsNotice(d)
	text := strings.Join(notice, "\n")

	var disabled string
	for _, line := range notice {
		if strings.Contains(line, "disabled") {
			disabled = line
		}
	}
	if !strings.Contains(disabled, "gitleaks") || !strings.Contains(disabled, "sast") {
		t.Errorf("want a disabled line naming gitleaks and sast:\n%s", text)
	}
	if strings.Contains(disabled, "osv-scanner") {
		t.Errorf("osv-scanner is missing, not disabled:\n%s", text)
	}
	for _, link := range []string{"/guide/scanners/gitleaks/", "/guide/scanners/sast/"} {
		if strings.Contains(text, link) {
			t.Errorf("a disabled Tool must not be offered as an install link %s:\n%s", link, text)
		}
	}
	if !strings.Contains(text, "registered: none") {
		t.Errorf("the only installed Tool is disabled, so none is registered:\n%s", text)
	}
}

// A host with nothing installed says so rather than printing an empty list.
func TestToolsNotice_SaysWhenNoScannerIsInstalled(t *testing.T) {
	d := security.Discover(func(string) (string, error) { return "", exec.ErrNotFound })
	text := strings.Join(toolsNotice(d), "\n")
	if !strings.Contains(text, "registered: none") {
		t.Errorf("want an explicit none:\n%s", text)
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
