// Package deployment holds the Deployment shape: which of the two things one
// Argus instance is (CONTEXT.md, ADR 0023).
//
// It is a vocabulary package with no dependencies, because the shape is read by
// packages that have no business knowing about each other — the daemon that
// derives it, the Channels whose extent depends on it, and `argus doctor`,
// whose checks stay cheap and dependency-free. Deriving the shape belongs to
// whoever holds the configuration (daemon.ShapeOf); naming it belongs here.
package deployment

// Shape is the Deployment shape of one Argus instance. It is **derived, never
// declared**: no key in argus.yaml selects it, and the one condition that
// decides it is whether an LLM Provider is configured.
type Shape int

const (
	// Toolbox is Argus with no Provider configured: it does not reason. The
	// deterministic capabilities stay — the scanners, the knowledge, the
	// Skills — and whoever calls supplies the reasoning.
	//
	// It is the zero value, and that is the safe way round: the Toolbox is the
	// floor both shapes stand on, so a Shape nobody set claims the smaller
	// promise rather than a reasoning it may not be able to do.
	Toolbox Shape = iota

	// Colleague is Argus with at least one Provider configured: it reasons on
	// its own behalf (Review, Consult, the memory curator, automatic PR review)
	// and has the whole Toolbox as well. It is a storey above the Toolbox, not
	// a fork of it.
	Colleague
)

// String renders the shape in the vocabulary CONTEXT.md fixes, which is also
// what every operator-facing surface prints.
func (s Shape) String() string {
	if s == Colleague {
		return "colleague"
	}
	return "toolbox"
}

// IsToolbox reports whether this instance has no Provider to reason with.
func (s Shape) IsToolbox() bool { return s != Colleague }
