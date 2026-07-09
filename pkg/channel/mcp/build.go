package mcp

import (
	"github.com/argusappsec/argus/pkg/daemon"
)

// DefaultAddr is the interim MCP listen address used until the front door slice
// (ADR 0015) collapses all HTTP channels onto daemon.http_addr. The channel
// keeps its own listener for now (config v2 scaffolding).
const DefaultAddr = ":8090"

// Build constructs the MCP channel. Auth is per-Person bearer tokens resolved
// against users.yaml at request time, so there are no credentials to load here;
// the channel carries only its interim listen address.
func Build(dc *daemon.Context) *Server {
	return NewServer(dc, Options{Addr: DefaultAddr})
}
