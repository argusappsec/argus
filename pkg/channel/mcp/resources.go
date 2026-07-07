package mcp

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/argusappsec/argus/pkg/auth"
)

// MCP Resources (ADR 0011, slice 5): the organization's knowledge exposed so the
// external AI can pull it as context directly, not only through review/consult.
// The surface is deliberately narrow — SOUL, the CONTEXT documents, and recent
// reports — and read-only. RBAC is enforced here at the resource layer and every
// read is attributed to the resolved Person in the audit log.

// Resource URIs use an argus:// scheme so the external AI can address each piece
// of org knowledge stably. Names within a path segment never contain separators
// (CONTEXT names are flat handles; report slugs replace path separators), so a
// single-segment scheme is unambiguous and traversal is rejected on read.
const (
	soulURI          = "argus://soul"
	contextURIPrefix = "argus://context/"
	reportURIPrefix  = "argus://report/"
)

// maxResourceReports caps how many recent reports are advertised, so a daemon
// with a long review history does not return an unbounded resource list. Reads
// of older reports by URI still work; only the listing is bounded.
const maxResourceReports = 20

// mimeMarkdown is the media type of every resource we expose — SOUL, CONTEXT
// documents, and reports are all markdown.
const mimeMarkdown = "text/markdown"

// resourceDecl is one entry in a resources/list result: the addressable URI, a
// human-readable name and description the external AI reads, and the media type.
type resourceDecl struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
}

// resourcesListResult is the resources/list response.
type resourcesListResult struct {
	Resources []resourceDecl `json:"resources"`
}

// resourceContents is one returned body in a resources/read result.
type resourceContents struct {
	URI      string `json:"uri"`
	MimeType string `json:"mimeType,omitempty"`
	Text     string `json:"text"`
}

// readResourceResult is the resources/read response (MCP ReadResourceResult).
type readResourceResult struct {
	Contents []resourceContents `json:"contents"`
}

// canReadResources reports whether role may list and read the org-knowledge
// Resources. Reading is read-only — it mutates nothing — so it mirrors consult:
// open to viewers as well as analysts and admins. A non-reading service role
// (ci-trigger / mirror-read) holding an MCP token sees nothing and cannot read.
func canReadResources(role auth.Role) bool {
	return role == auth.RoleAdmin || role == auth.RoleAnalyst || role == auth.RoleViewer
}

// errResourceDenied is the resource-layer refusal a caller without a reading
// role gets, phrased so the external AI relays it to the developer.
const errResourceDenied = "permission denied: reading Argus resources requires the viewer, analyst, or admin role on this channel"

// handleResourcesList answers resources/list: enforce RBAC, enumerate SOUL, the
// CONTEXT documents, and the recent reports, and attribute the listing to the
// resolved Person. A caller without a reading role gets an empty list (it sees
// nothing) rather than an error, which clients tolerate gracefully.
func (s *Server) handleResourcesList(principal auth.Principal, req rpcRequest) rpcResponse {
	if !canReadResources(principal.Role) {
		s.audit("mcp_resources_list_denied", principal, map[string]any{"reason": "insufficient role"})
		return result(req.ID, resourcesListResult{Resources: []resourceDecl{}})
	}
	res := s.listResources()
	s.audit("mcp_resources_list", principal, map[string]any{"count": len(res)})
	return result(req.ID, resourcesListResult{Resources: res})
}

// listResources enumerates the org knowledge available as Resources, in a stable
// order: SOUL, then CONTEXT documents (alphabetical), then recent reports
// (newest first). Missing pieces (no SOUL, no context dir, no reports) are simply
// absent, never an error.
func (s *Server) listResources() []resourceDecl {
	out := []resourceDecl{}
	if fileExists(s.soulPath()) {
		out = append(out, resourceDecl{
			URI:         soulURI,
			Name:        "SOUL",
			Description: "The organization's security identity: stack, infra, compliance posture, risk tolerance, and persona.",
			MimeType:    mimeMarkdown,
		})
	}
	for _, name := range listMarkdown(s.contextDir()) {
		base := strings.TrimSuffix(name, ".md")
		out = append(out, resourceDecl{
			URI:         contextURIPrefix + base,
			Name:        base,
			Description: "Background knowledge document about the organization/environment.",
			MimeType:    mimeMarkdown,
		})
	}
	for _, r := range recentReports(s.reportsDir(), maxResourceReports) {
		out = append(out, resourceDecl{
			URI:         reportURIPrefix + r.slug + "/" + r.sha,
			Name:        r.slug + "@" + r.sha,
			Description: "A past security review report.",
			MimeType:    mimeMarkdown,
		})
	}
	return out
}

// handleResourceRead answers resources/read: enforce RBAC, resolve the URI to a
// file under the daemon home, and return its content. Every read is attributed
// to the resolved Person. A denied role rides a JSON-RPC error (there is no
// CallToolResult shape for resources); an unknown or unreadable URI is a
// resource-not-found error.
func (s *Server) handleResourceRead(principal auth.Principal, req rpcRequest) rpcResponse {
	if !canReadResources(principal.Role) {
		s.audit("mcp_resource_read_denied", principal, map[string]any{"reason": "insufficient role"})
		return errorResponse(req.ID, codeForbidden, errResourceDenied)
	}
	var params struct {
		URI string `json:"uri"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		// A malformed read by an authenticated reader is still attributed, so the
		// audit trail records every read attempt this Person made (not only the
		// well-formed ones).
		s.audit("mcp_resource_read", principal, map[string]any{"ok": false, "reason": "invalid params"})
		return errorResponse(req.ID, codeInvalidParams, "invalid resources/read params")
	}
	uri := strings.TrimSpace(params.URI)
	text, err := s.readResource(uri)
	if err != nil {
		s.audit("mcp_resource_read", principal, map[string]any{"uri": uri, "ok": false})
		return errorResponse(req.ID, codeResourceNotFound, err.Error())
	}
	s.audit("mcp_resource_read", principal, map[string]any{"uri": uri, "ok": true})
	return result(req.ID, readResourceResult{
		Contents: []resourceContents{{URI: uri, MimeType: mimeMarkdown, Text: text}},
	})
}

// readResource resolves a resource URI to file content. It dispatches on the
// scheme prefix and rejects any path traversal — resource handles are flat, so a
// separator or parent reference in the addressed name is an error, not a path.
func (s *Server) readResource(uri string) (string, error) {
	switch {
	case uri == soulURI:
		return readFile(s.soulPath())
	case strings.HasPrefix(uri, contextURIPrefix):
		return s.readContextResource(strings.TrimPrefix(uri, contextURIPrefix))
	case strings.HasPrefix(uri, reportURIPrefix):
		return s.readReportResource(strings.TrimPrefix(uri, reportURIPrefix))
	default:
		return "", fmt.Errorf("unknown resource: %q", uri)
	}
}

// readContextResource reads one CONTEXT document by its flat name. The .md
// extension is optional in the URI; traversal is rejected.
func (s *Server) readContextResource(name string) (string, error) {
	if name == "" || strings.ContainsAny(name, "/\\") || strings.Contains(name, "..") {
		return "", fmt.Errorf("invalid context document %q", name)
	}
	if !strings.HasSuffix(name, ".md") {
		name += ".md"
	}
	return readUnder(s.contextDir(), name)
}

// readReportResource reads one report by its "<slug>/<sha>" handle. Report slugs
// never contain path separators (report.Slugify replaces them) and the sha is
// hex, so anything else is rejected before touching disk.
func (s *Server) readReportResource(rest string) (string, error) {
	slug, sha, ok := strings.Cut(rest, "/")
	if !ok || slug == "" || sha == "" ||
		strings.ContainsAny(slug, "/\\") || strings.Contains(slug, "..") ||
		strings.ContainsAny(sha, "/\\") || strings.Contains(sha, "..") {
		return "", fmt.Errorf("invalid report resource %q", rest)
	}
	return readUnder(s.reportsDir(), filepath.Join(slug, sha+".md"))
}

// soulPath / contextDir / reportsDir derive the on-disk layout from the daemon
// home, mirroring how daemon.Build wires SOUL.md, context/, and the report
// Writer — the channel reads the same files those produce.
func (s *Server) soulPath() string   { return filepath.Join(s.dc.Home, "SOUL.md") }
func (s *Server) contextDir() string { return filepath.Join(s.dc.Home, "context") }
func (s *Server) reportsDir() string { return filepath.Join(s.dc.Home, "reports") }

// reportRef is a discovered report file, keyed by its slug/sha and modtime so
// the listing can surface the most recent ones.
type reportRef struct {
	slug string
	sha  string
	mod  time.Time
}

// recentReports walks <home>/reports/<slug>/<sha>.md and returns up to limit of
// them, newest first. A missing reports dir yields nothing, not an error.
func recentReports(dir string, limit int) []reportRef {
	slugs, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var refs []reportRef
	for _, sd := range slugs {
		if !sd.IsDir() {
			continue
		}
		files, err := os.ReadDir(filepath.Join(dir, sd.Name()))
		if err != nil {
			continue
		}
		for _, f := range files {
			if f.IsDir() || !strings.HasSuffix(f.Name(), ".md") {
				continue
			}
			info, err := f.Info()
			if err != nil {
				continue
			}
			refs = append(refs, reportRef{
				slug: sd.Name(),
				sha:  strings.TrimSuffix(f.Name(), ".md"),
				mod:  info.ModTime(),
			})
		}
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].mod.After(refs[j].mod) })
	if len(refs) > limit {
		refs = refs[:limit]
	}
	return refs
}

// listMarkdown returns the *.md filenames in dir, sorted. A missing dir yields
// nothing (no context = no resources, not an error).
func listMarkdown(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names
}

// fileExists reports whether path is an existing regular file.
func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// readFile returns the content of path as a string.
func readFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// readUnder reads base/rel after confirming the resolved path stays under base —
// defense in depth on top of the per-handle traversal checks.
func readUnder(base, rel string) (string, error) {
	absBase, err := filepath.Abs(base)
	if err != nil {
		return "", err
	}
	absPath, err := filepath.Abs(filepath.Join(base, rel))
	if err != nil {
		return "", err
	}
	if absPath != absBase && !strings.HasPrefix(absPath, absBase+string(filepath.Separator)) {
		return "", fmt.Errorf("resource path escapes its directory")
	}
	return readFile(absPath)
}
