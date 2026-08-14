package mcp

import (
	"context"
	"encoding/json"
	"slices"

	"github.com/argusappsec/argus/pkg/auth"
	"github.com/argusappsec/argus/pkg/daemon"
	"github.com/argusappsec/argus/pkg/deployment"
)

// The MCP channel keeps one endpoint and one handshake, and has two extents —
// one per Deployment shape (ADR 0023). This file is the single place that
// answers "what does this shape expose?": the tool listing, the handshake's
// capability set, and what a client gets back when it names something this
// deployment does not serve. Nothing else in the channel asks whether Argus can
// reason.

// toolStartReviewLocal / toolStartReviewGitHub are the registry tools that
// point Argus's own review loop at a tree (pkg/tool). The MCP surface has never
// served them — the low-level loop stays inside Argus (ADR 0011) — but a client
// that has read Argus's documentation may still name one, so the surface knows
// them by name in order to answer honestly.
const (
	toolStartReviewLocal  = "start_review_local"
	toolStartReviewGitHub = "start_review_github"
)

// capabilityHandler serves one tools/call. sessionID is the caller's MCP session
// (empty for a sessionless one-shot client).
type capabilityHandler func(ctx context.Context, principal auth.Principal, sessionID string, req rpcRequest, args json.RawMessage) rpcResponse

// capability is one tool the MCP channel can serve: the declaration a client
// reads in tools/list, the handler that runs it, and the admission decision
// that says whether it survives into a Toolbox. Admission is recorded per
// capability and read from one place, so a capability added later is exposed
// because someone decided it should be, never by default.
type capability struct {
	decl   toolDecl
	handle capabilityHandler

	// needsReasoning marks a capability whose work is Argus's own agent loop.
	// A Toolbox has no Provider and therefore no loop, so there it does not
	// exist at all: absent from the listing, and named as the reason when
	// called.
	needsReasoning bool
}

// catalog is every capability this channel knows how to serve, in the order a
// client sees them in tools/list, with its handler already bound to the server.
// It is built per request and nothing caches it, which is what lets the extent
// follow a shape — and a Registry — that changed after the daemon started. The
// cost is assembling the declarations and one tool Registry per request, which
// is a map of plain data next to the I/O every request already does.
//
// The two coarse capabilities are written here because their work is Argus's
// own agent loop. Everything deterministic is projected from the daemon's tool
// Registry instead (toolbox.go) — one source, no hand-maintained second list.
func (s *Server) catalog() []capability {
	caps := []capability{
		{decl: reviewToolDecl(), handle: s.handleReview, needsReasoning: true},
		{decl: consultToolDecl(), handle: s.handleConsult, needsReasoning: true},
	}
	return append(caps, s.registryCapabilities()...)
}

// reasoningOnlyNames are tool names that exist only where Argus reasons but are
// not capabilities of this channel, so the catalog cannot carry them. They are
// still recognized here: a client that names one in a Toolbox is told why it is
// gone rather than that the tool is unknown.
var reasoningOnlyNames = []string{toolStartReviewLocal, toolStartReviewGitHub}

// surface is the extent of the catalog one Deployment shape serves.
//
// It is derived per request from the daemon's current shape and never captured
// when the channel is constructed, so a daemon that has a Provider configured
// after it started serves the larger surface to the next client that asks — no
// rebuild, no restart of the channel.
type surface struct {
	shape deployment.Shape
	caps  []capability
}

// surface reads the daemon's Deployment shape as it is right now. Every request
// that depends on the extent goes through here.
func (s *Server) surface() surface {
	return surface{shape: s.dc.Shape, caps: s.catalog()}
}

// admits reports whether this shape serves the given capability.
func (sf surface) admits(c capability) bool {
	return !c.needsReasoning || !sf.shape.IsToolbox()
}

// tools is what tools/list returns for this shape: the admitted declarations,
// always a list (never null on the wire).
func (sf surface) tools() []toolDecl {
	decls := make([]toolDecl, 0, len(sf.caps))
	for _, c := range sf.caps {
		if sf.admits(c) {
			decls = append(decls, c.decl)
		}
	}
	return decls
}

// lookup finds the capability this shape serves under name.
func (sf surface) lookup(name string) (capability, bool) {
	for _, c := range sf.caps {
		if c.decl.Name == name && sf.admits(c) {
			return c, true
		}
	}
	return capability{}, false
}

// withholds reports whether name is something Argus has, that this shape cannot
// serve. It separates "gone because this daemon does not reason" from "never
// heard of it", which are different things to tell a client.
func (sf surface) withholds(name string) bool {
	for _, c := range sf.caps {
		if c.decl.Name == name {
			return !sf.admits(c)
		}
	}
	return sf.shape.IsToolbox() && slices.Contains(reasoningOnlyNames, name)
}

// capabilities is the handshake's capability set: what this shape will actually
// serve, not a fixed advertisement. Resources are the organization's knowledge
// and need no Provider, so they are offered in both shapes; tools are offered
// when this shape serves any, so the handshake never promises a listing that
// comes back empty.
func (sf surface) capabilities() map[string]any {
	caps := map[string]any{"resources": map[string]any{}}
	if len(sf.tools()) > 0 {
		caps["tools"] = map[string]any{}
	}
	return caps
}

// withheldReason is what a client is told when it names a capability this
// deployment does not serve. It names the tool, then gives the daemon's single
// explanation of the shape (daemon.ErrNoReasoning), so an AI that learned the
// name elsewhere can tell the developer what to configure instead of merely
// reporting a failure.
func withheldReason(name string) string {
	return name + " is not available here — " + daemon.ErrNoReasoning.Error()
}
