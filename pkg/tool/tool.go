// Package tool defines the Tool interface, a Registry, and the built-in
// environment tools the security-review agent uses to inspect a checked-out
// repository.
//
// Each tool is sandboxed to a root directory (the temp clone) and refuses to
// resolve paths that escape that root.
package tool

import (
	"context"
	"maps"
	"sort"

	"github.com/argusappsec/argus/pkg/provider"
)

// Tool is the contract every callable capability satisfies.
type Tool interface {
	Name() string
	Description() string
	Schema() map[string]any
	Execute(ctx context.Context, args map[string]any) (string, error)
}

// Registry holds the set of tools available to one agent run, and records for
// each of them whether it is admitted onto Argus's external surfaces.
type Registry struct {
	entries map[string]entry
}

// entry is one registered tool plus its admission decision. Admission is stored
// per tool rather than derived from a list elsewhere, so the Registry is the
// single place that knows both which Tools exist and which of them a caller
// outside Argus may see (ADR 0023).
type entry struct {
	tool Tool

	// exposed marks a tool admitted onto Argus's external surfaces — today the
	// MCP Toolbox surface, which is a projection of this Registry. It is set
	// only by Expose: registering a tool never admits it, so a tool added for
	// Argus's own agent loop cannot leak outwards by default.
	exposed bool
}

// NewRegistry creates an empty Registry.
func NewRegistry() *Registry {
	return &Registry{entries: map[string]entry{}}
}

// Register adds t to the registry for Argus's own agent loop, replacing any
// existing tool with the same name. It does not admit t onto any external
// surface — use Expose for that, deliberately. The decision travels with the
// registration, so registering over an exposed tool withdraws it from the
// surface rather than inheriting an admission granted to something else.
func (r *Registry) Register(t Tool) {
	r.entries[t.Name()] = entry{tool: t}
}

// Expose registers t and admits it onto Argus's external surfaces. The
// admission rule is ADR 0023's: expose only what the caller does not already
// have — the scanners and the organization's knowledge, never the file tools
// the calling agent has already and better.
func (r *Registry) Expose(t Tool) {
	r.entries[t.Name()] = entry{tool: t, exposed: true}
}

// Exposed returns the tools admitted by Expose, sorted by name so a surface
// projected from this Registry is in a stable order.
func (r *Registry) Exposed() []Tool {
	out := make([]Tool, 0, len(r.entries))
	for _, e := range r.entries {
		if e.exposed {
			out = append(out, e.tool)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}

// Get returns the tool with the given name.
func (r *Registry) Get(name string) (Tool, bool) {
	e, ok := r.entries[name]
	if !ok {
		return nil, false
	}
	return e.tool, true
}

// With returns a new Registry holding this one's tools plus extra (replacing by
// name), carrying each existing tool's admission decision across. The receiver
// is left unchanged, so a caller can assemble a per-run tool set — e.g. a
// channel injecting request-scoped tools whose dependencies or authorization
// differ per turn — without mutating a registry shared across concurrent runs.
// The extra tools are registered, not exposed: a request-scoped tool is for the
// run that supplied it.
func (r *Registry) With(extra ...Tool) *Registry {
	nr := &Registry{entries: make(map[string]entry, len(r.entries)+len(extra))}
	maps.Copy(nr.entries, r.entries)
	for _, t := range extra {
		nr.entries[t.Name()] = entry{tool: t}
	}
	return nr
}

// Decls returns the provider-facing declarations for all registered tools,
// admitted or not — Argus's own agent loop sees everything it registered.
// Sorted by name so prompt-token usage is deterministic.
func (r *Registry) Decls() []provider.ToolDecl {
	out := make([]provider.ToolDecl, 0, len(r.entries))
	for _, e := range r.entries {
		out = append(out, provider.ToolDecl{
			Name:        e.tool.Name(),
			Description: e.tool.Description(),
			Schema:      e.tool.Schema(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
