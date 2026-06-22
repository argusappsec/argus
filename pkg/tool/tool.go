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

	"github.com/redcarbon-dev/argus/pkg/provider"
)

// Tool is the contract every callable capability satisfies.
type Tool interface {
	Name() string
	Description() string
	Schema() map[string]any
	Execute(ctx context.Context, args map[string]any) (string, error)
}

// Registry holds the set of tools available to one agent run.
type Registry struct {
	tools map[string]Tool
}

// NewRegistry creates an empty Registry.
func NewRegistry() *Registry {
	return &Registry{tools: map[string]Tool{}}
}

// Register adds t to the registry, replacing any existing tool with the same name.
func (r *Registry) Register(t Tool) {
	r.tools[t.Name()] = t
}

// Get returns the tool with the given name.
func (r *Registry) Get(name string) (Tool, bool) {
	t, ok := r.tools[name]
	return t, ok
}

// With returns a new Registry holding this one's tools plus extra (replacing by
// name). The receiver is left unchanged, so a caller can assemble a per-run tool
// set — e.g. a channel injecting request-scoped tools whose dependencies or
// authorization differ per turn — without mutating a registry shared across
// concurrent runs.
func (r *Registry) With(extra ...Tool) *Registry {
	nr := &Registry{tools: make(map[string]Tool, len(r.tools)+len(extra))}
	maps.Copy(nr.tools, r.tools)
	for _, t := range extra {
		nr.tools[t.Name()] = t
	}
	return nr
}

// Decls returns the provider-facing declarations for all registered tools,
// sorted by name so prompt-token usage is deterministic.
func (r *Registry) Decls() []provider.ToolDecl {
	out := make([]provider.ToolDecl, 0, len(r.tools))
	for _, t := range r.tools {
		out = append(out, provider.ToolDecl{
			Name:        t.Name(),
			Description: t.Description(),
			Schema:      t.Schema(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
