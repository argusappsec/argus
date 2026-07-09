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
			fmt.Fprintf(cmd.OutOrStdout(), "argusd: listening on %s\n", dc.SocketPath)

			channels := []daemon.Channel{uds.NewServer(dc)}
			// The GitHub App channel starts only when a github channel is
			// declared (ADR 0015); its outbound credentials come from the
			// github codehost. Validate (in daemon.Build) guarantees the
			// codehost is present, so the lookup cannot miss.
			if ch, ok := cfg.Channel(config.ChannelTypeGitHub); ok {
				host, _ := cfg.CodeHost(config.CodeHostTypeGitHub)
				gh, err := ghchannel.Build(dc, host, ch)
				if err != nil {
					return fmt.Errorf("argusd: github channel: %w", err)
				}
				channels = append(channels, gh)
				fmt.Fprintf(cmd.OutOrStdout(), "argusd: github webhook on %s\n", ghchannel.DefaultAddr)
			}
			// The MCP channel starts only when an mcp channel is declared
			// (ADR 0011); an absent channels: entry leaves the daemon
			// socket-only.
			if _, ok := cfg.Channel(config.ChannelTypeMCP); ok {
				channels = append(channels, mcpchannel.Build(dc))
				fmt.Fprintf(cmd.OutOrStdout(), "argusd: mcp on %s\n", mcpchannel.DefaultAddr)
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
