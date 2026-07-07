package report_test

import (
	"testing"

	"github.com/argusappsec/argus/pkg/report"
)

func TestComputeFindingID_Deterministic(t *testing.T) {
	id1 := report.ComputeFindingID("S101", `password := "secret"`)
	id2 := report.ComputeFindingID("S101", `password := "secret"`)
	if id1 != id2 {
		t.Errorf("same input must yield same id; got %q vs %q", id1, id2)
	}
}

func TestComputeFindingID_StableAcrossWhitespace(t *testing.T) {
	id1 := report.ComputeFindingID("S101", `password := "secret"`)
	id2 := report.ComputeFindingID("S101", "password   :=\t\"secret\"")
	id3 := report.ComputeFindingID("S101", "\n\tpassword := \"secret\"\n")
	if id1 != id2 || id1 != id3 {
		t.Errorf("ids must be stable across whitespace; got %q, %q, %q", id1, id2, id3)
	}
}

func TestComputeFindingID_DifferOnRuleID(t *testing.T) {
	a := report.ComputeFindingID("S101", `password := "secret"`)
	b := report.ComputeFindingID("S102", `password := "secret"`)
	if a == b {
		t.Errorf("different rule IDs must yield different finding IDs; both %q", a)
	}
}

func TestComputeFindingID_DifferOnSnippetContent(t *testing.T) {
	a := report.ComputeFindingID("S101", `password := "secret"`)
	b := report.ComputeFindingID("S101", `password := "other"`)
	if a == b {
		t.Errorf("different snippet content must yield different ids; both %q", a)
	}
}
