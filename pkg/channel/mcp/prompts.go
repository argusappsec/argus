package mcp

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/argusappsec/argus/pkg/auth"
)

// MCP prompts are the second way the organization's Skills reach a caller
// (ADR 0023): the Tools serve an agent that goes looking by name, the prompts
// serve a user who does not know Argus's tool names and should not have to —
// the workflow appears in their own client's prompt menu. A Toolbox that
// nobody thinks to call decays to nothing, so this is what makes the surface
// discoverable.
//
// It is the same Skill Catalog behind both, read the same way, with the
// whole-bundle override the daemon already applies. There is deliberately no
// prompt store: a Skill authored once is one Skill, whichever surface fetches
// it.

// promptDecl is one entry in a prompts/list result: the Skill's name as the
// client shows it in its menu, and the Skill's own description as the
// when-to-use hint. Skills take no parameters — the body is the whole
// instruction — so no arguments are declared.
type promptDecl struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// promptsListResult is the prompts/list response.
type promptsListResult struct {
	Prompts []promptDecl `json:"prompts"`
}

// promptContent is one content block of a prompt message. Skill bodies are
// markdown, so only text blocks are produced.
type promptContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// promptMessage is one message a retrieved prompt expands into. A Skill is
// instructions for whoever is reasoning, so it arrives as a user message.
type promptMessage struct {
	Role    string        `json:"role"`
	Content promptContent `json:"content"`
}

// getPromptResult is the prompts/get response (MCP GetPromptResult).
type getPromptResult struct {
	Description string          `json:"description,omitempty"`
	Messages    []promptMessage `json:"messages"`
}

// errPromptDenied is the refusal a caller without a reading role gets on
// prompts/get, phrased so the external AI relays it to the developer.
const errPromptDenied = "permission denied: reading Argus prompts requires the viewer, analyst, or admin role on this channel"

// handlePromptsList answers prompts/list: the Skill catalog, one prompt per
// Skill, sorted by name so a client's menu is stable across connections. Role
// enforcement is canReadKnowledge's, the Resources' — a Skill read mutates
// nothing, so it is a read-only caller's to make on this surface exactly as it
// is on the tools surface (viewerReads). A caller without a reading Role gets
// an empty list rather than an error, which clients tolerate gracefully.
func (s *Server) handlePromptsList(principal auth.Principal, req rpcRequest) rpcResponse {
	if !canReadKnowledge(principal.Role) {
		s.audit("mcp_prompts_list_denied", principal, map[string]any{"reason": "insufficient role"})
		return result(req.ID, promptsListResult{Prompts: []promptDecl{}})
	}
	prompts := s.listPrompts()
	s.audit("mcp_prompts_list", principal, map[string]any{"count": len(prompts)})
	return result(req.ID, promptsListResult{Prompts: prompts})
}

// listPrompts projects the Skill catalog into prompt declarations. Malformed
// Skills are skipped exactly as list_skills skips them: a parse error is the
// author's to fix (argus skill ls reports it), not noise for the caller.
func (s *Server) listPrompts() []promptDecl {
	skills, _ := s.dc.Skills.List()
	out := make([]promptDecl, 0, len(skills))
	for _, sk := range skills {
		out = append(out, promptDecl{Name: sk.Name, Description: sk.Description})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// handlePromptGet answers prompts/get: the named Skill's body, resolved through
// the same Catalog — so a user-curated bundle that claims a built-in's name
// wins here too, body and supporting files together. An unknown name is an
// invalid-params error, which is what the protocol reserves for a prompt the
// server does not have.
func (s *Server) handlePromptGet(principal auth.Principal, req rpcRequest) rpcResponse {
	if !canReadKnowledge(principal.Role) {
		s.audit("mcp_prompt_get_denied", principal, map[string]any{"reason": "insufficient role"})
		return errorResponse(req.ID, codeForbidden, errPromptDenied)
	}
	var params struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		s.audit("mcp_prompt_get", principal, map[string]any{"ok": false, "reason": "invalid params"})
		return errorResponse(req.ID, codeInvalidParams, "invalid prompts/get params")
	}
	name := strings.TrimSpace(params.Name)
	sk, err := s.dc.Skills.Load(name)
	if err != nil {
		s.audit("mcp_prompt_get", principal, map[string]any{"prompt": name, "ok": false})
		return errorResponse(req.ID, codeInvalidParams, "unknown prompt: "+name)
	}
	s.audit("mcp_prompt_get", principal, map[string]any{"prompt": name, "ok": true})
	return result(req.ID, getPromptResult{
		Description: sk.Description,
		Messages: []promptMessage{{
			Role:    "user",
			Content: promptContent{Type: "text", Text: sk.Content},
		}},
	})
}
