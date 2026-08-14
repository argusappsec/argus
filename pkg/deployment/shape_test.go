package deployment_test

import (
	"testing"

	"github.com/argusappsec/argus/pkg/deployment"
)

// The zero value is the Toolbox, and that is load-bearing: a Context, an
// Options struct or any other carrier of a Shape that nobody set must claim the
// floor rather than a reasoning capability it may not have.
func TestZeroValueIsTheToolbox(t *testing.T) {
	var unset deployment.Shape
	if !unset.IsToolbox() {
		t.Errorf("the zero Shape reports %v; an unset shape must be the toolbox", unset)
	}
	if deployment.Colleague.IsToolbox() {
		t.Error("a Colleague must not report itself as a toolbox")
	}
}

func TestStringUsesTheDomainVocabulary(t *testing.T) {
	if got := deployment.Toolbox.String(); got != "toolbox" {
		t.Errorf("Toolbox.String() = %q", got)
	}
	if got := deployment.Colleague.String(); got != "colleague" {
		t.Errorf("Colleague.String() = %q", got)
	}
}
