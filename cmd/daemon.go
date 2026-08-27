package cmd

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	ghchannel "github.com/argusappsec/argus/pkg/channel/github"
	mcpchannel "github.com/argusappsec/argus/pkg/channel/mcp"
	"github.com/argusappsec/argus/pkg/channel/uds"
	"github.com/argusappsec/argus/pkg/config"
	"github.com/argusappsec/argus/pkg/daemon"
	"github.com/argusappsec/argus/pkg/deployment"
)

// daemonCmd runs argusd: the long-running shared daemon every Channel lives
// in (ADR 0001/0004). Today it hosts one Channel — the local Unix socket the
// CLI connects to; Slack/MCP/webhook plug into the same contract later.
func daemonCmd() *cobra.Command {
	var homeDir string
	c := &cobra.Command{
		Use:   "daemon",
		Short: "Run the Argus daemon (argusd).",
		Long: "Run the long-running Argus daemon. Channels (local socket today; Slack,\n" +
			"MCP and webhooks tomorrow) accept inbound requests, resolve the caller\n" +
			"to a Principal, and dispatch to the agent. One process per organization.",
		RunE: func(cmd *cobra.Command, args []string) error {
			home, err := resolveHome(homeDir)
			if err != nil {
				return err
			}
			cfg, err := config.LoadConfig(filepath.Join(home, "argus.yaml"))
			if err != nil {
				return err
			}
			dc, err := daemon.Build(home, cfg)
			if err != nil {
				return err
			}
			defer dc.Close()

			// Fail fast when another daemon already owns the socket, before
			// the channel runner would mask it behind restart backoff.
			if probe, err := net.DialTimeout("unix", dc.SocketPath, time.Second); err == nil {
				probe.Close()
				return fmt.Errorf("argusd is already running on %s", dc.SocketPath)
			}

			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			fmt.Fprintf(cmd.OutOrStdout(), "argusd: home %s\n", home)
			for _, line := range shapeNotice(dc.Shape) {
				fmt.Fprintln(cmd.OutOrStdout(), line)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "argusd: listening on %s\n", dc.SocketPath)

			// The UDS channel owns its own transport (a Unix socket); it runs
			// as a loop-owning Channel with restart-with-backoff (ADR 0004).
			channels := []daemon.Channel{uds.NewServer(dc)}

			// HTTP channels don't own listeners: they register fixed paths on
			// the daemon's single front door (ADR 0015). Collect the configured
			// ones, then stand up one HTTP server for all of them.
			var httpChannels []daemon.HTTPChannel
			// The GitHub App channel is present only when a github channel is
			// declared; it clones and calls the API through the shared
			// authenticated codehost (dc.CodeHost), which daemon.Build built from
			// codehosts:. Validate guarantees that codehost is present.
			if ch, ok := cfg.Channel(config.ChannelTypeGitHub); ok {
				gh, err := ghchannel.Build(dc, ch)
				if err != nil {
					return fmt.Errorf("argusd: github channel: %w", err)
				}
				httpChannels = append(httpChannels, gh)
			}
			// The MCP channel is present only when an mcp channel is declared
			// (ADR 0011).
			if _, ok := cfg.Channel(config.ChannelTypeMCP); ok {
				httpChannels = append(httpChannels, mcpchannel.NewServer(dc))
			}

			// The front door starts only when at least one HTTP channel is
			// configured; a minimal install stays socket-only, listening on
			// nothing it doesn't use.
			if len(httpChannels) > 0 {
				addr := cfg.Daemon.HTTPAddress()
				channels = append(channels, daemon.NewFrontDoor(dc, addr, httpChannels...))
				fmt.Fprintf(cmd.OutOrStdout(), "argusd: http front door on %s\n", addr)
				for _, hc := range httpChannels {
					for _, rt := range hc.Routes() {
						fmt.Fprintf(cmd.OutOrStdout(), "argusd:   %s → %s\n", rt.Pattern, hc.Name())
					}
				}
			}

			daemon.RunChannels(ctx, dc, channels...)

			// Graceful shutdown: connections are gone (their runs died with
			// them); wait for pending memory curations before exiting.
			fmt.Fprintln(cmd.OutOrStdout(), "argusd: draining memory curations")
			dc.Sessions.Drain(30 * time.Second)
			return nil
		},
	}
	c.Flags().StringVar(&homeDir, "home", "", "Override ~/.argus home directory")
	return c
}

// shapeNotice is what argusd says at startup about the Deployment shape it
// derived (ADR 0023). A Colleague gets one line. A Toolbox gets the
// consequences too, because the operator has to learn here why Review is
// missing — the alternative is learning it while looking for it.
func shapeNotice(shape deployment.Shape) []string {
	if !shape.IsToolbox() {
		return []string{"argusd: deployment shape: colleague (an LLM Provider is configured)"}
	}
	return []string{
		"argusd: deployment shape: toolbox — no LLM Provider is configured",
		"argusd:   Argus does not reason on its own behalf here: review, consult and automatic",
		"argusd:   PR review are unavailable. Its scanners, the organization's knowledge and its",
		"argusd:   Skills are served over MCP, for an AI that reasons on your machine to drive.",
		"argusd:   Configure a provider in argus.yaml (`argus init`) to run as a colleague.",
	}
}
