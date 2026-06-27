package mcp

import (
	"github.com/redcarbon-dev/argus/pkg/config"
	"github.com/redcarbon-dev/argus/pkg/daemon"
)

// Build constructs the MCP channel from its config section. Auth is per-Person
// bearer tokens resolved against users.yaml at request time, so there are no
// credentials to load here — only the listen address.
func Build(dc *daemon.Context, cfg config.MCPConfig) *Server {
	return NewServer(dc, Options{Addr: cfg.ListenAddr()})
}
