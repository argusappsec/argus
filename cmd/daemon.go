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

	"github.com/redcarbon-dev/argus/pkg/channel/uds"
	"github.com/redcarbon-dev/argus/pkg/config"
	"github.com/redcarbon-dev/argus/pkg/daemon"
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

			daemon.RunChannels(ctx, dc, uds.NewServer(dc))

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
