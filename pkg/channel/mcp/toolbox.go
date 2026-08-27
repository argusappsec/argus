package mcp

import (
	"context"
	"encoding/json"
	"slices"

	"github.com/argusappsec/argus/pkg/auth"
	"github.com/argusappsec/argus/pkg/tool"
)

// The deterministic half of the surface — the capabilities that need no
// reasoning — is a projection of the daemon's tool Registry (ADR 0023), never a
// second declaration list that would drift the day a Tool is added. The
// Registry carries the admission decision per Tool; this file turns the
// admitted ones into MCP capabilities and enforces the caller's Role on the way
// through.

// viewerReads names the projected capabilities a read-only Role may call.
// Everything else on the surface needs analyst or admin, so a capability
// admitted later — a knowledge write, a scanner — is refused to a viewer until
// somebody says otherwise here. The list is stated this way round on purpose:
// forgetting it costs a viewer a read, where the other way round it would cost
// the organization a write.
//
// This is the Channel's Role policy, not a second declaration of what the
// surface holds — what exists and what is admitted still come from the Registry
// alone, and a name here the Registry does not expose simply never matches.
// Enforcement lives at the Channel, the way review's does: CONTEXT.md puts it in
// the Channels and not in the shared Registry, which Argus's own agent loop runs
// against too.
var viewerReads = []string{"list_context", "read_context", "list_skills", "read_skill", "read_skill_file"}

// errToolDenied is the refusal a read-only caller gets, naming the capability
// so the external AI can relay it to the developer.
func errToolDenied(name string) string {
	return "permission denied: " + name + " requires the analyst or admin role" + roleIsReadOnly
}

// registryCapabilities projects the daemon's tool Registry onto the MCP
// surface: one capability per admitted Tool, in the Registry's stable order.
// They need no Provider, so they are served in both Deployment shapes — the
// Toolbox is the floor the Colleague stands on.
func (s *Server) registryCapabilities() []capability {
	admitted := s.dc.NewToolRegistry().Exposed()
	caps := make([]capability, 0, len(admitted))
	for _, t := range admitted {
		caps = append(caps, capability{
			decl:   registryToolDecl(t),
			handle: s.registryToolHandler(t),
		})
	}
	return caps
}

// registryToolDecl is a Tool's wire declaration. The Tool's own description and
// schema are what the external AI reads, so the two surfaces describe a
// capability identically and there is nothing to keep in step.
func registryToolDecl(t tool.Tool) toolDecl {
	return toolDecl{Name: t.Name(), Description: t.Description(), InputSchema: t.Schema()}
}

// registryToolHandler runs one projected Tool for an authenticated caller:
// Role gate, execute, audit. Every call is attributed to the Principal the
// bearer token resolved to, so the audit record is as complete in a Toolbox as
// it is in a Colleague. A Tool failure rides a successful JSON-RPC response as a
// tool error, so the calling AI relays the message.
func (s *Server) registryToolHandler(t tool.Tool) capabilityHandler {
	readable := slices.Contains(viewerReads, t.Name())
	return func(ctx context.Context, principal auth.Principal, _ string, req rpcRequest, rawArgs json.RawMessage) rpcResponse {
		if !readable && !atLeastAnalyst(principal.Role) {
			s.audit("mcp_tool_denied", principal, map[string]any{"tool": t.Name(), "reason": "insufficient role"})
			return result(req.ID, toolError(errToolDenied(t.Name())))
		}

		args := map[string]any{}
		if len(rawArgs) > 0 {
			if err := json.Unmarshal(rawArgs, &args); err != nil {
				return result(req.ID, toolError("invalid arguments for "+t.Name()+": "+err.Error()))
			}
		}

		out, err := t.Execute(ctx, args)
		if err != nil {
			s.audit("mcp_tool_failed", principal, map[string]any{"tool": t.Name(), "error": err.Error()})
			return result(req.ID, toolError(err.Error()))
		}
		s.audit("mcp_tool_call", principal, map[string]any{"tool": t.Name()})
		return result(req.ID, toolCallResult{Content: textContent(out)})
	}
}
