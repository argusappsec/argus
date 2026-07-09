// Package cmd is the cobra command tree for the argus CLI.
package cmd

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "argus",
	Short: "Argus — security review agent",
	Long:  "Argus is an LLM-driven security review agent for GitHub repositories.",
}

// Root returns the root command. Tests can use this to invoke subcommands
// in-process.
func Root() *cobra.Command {
	return rootCmd
}

func init() {
	chat := chatCmd()
	rootCmd.AddCommand(chat)
	rootCmd.AddCommand(reviewCmd())
	rootCmd.AddCommand(initCmd())
	rootCmd.AddCommand(doctorCmd())
	rootCmd.AddCommand(skillCmd())
	rootCmd.AddCommand(daemonCmd())
	rootCmd.AddCommand(userCmd())
	rootCmd.AddCommand(codehostCmd())

	// `argus` with no arguments opens the interactive chat — the primary UX.
	// Explicit subcommands (review, chat, init, doctor, future ones) still
	// work as before.
	rootCmd.RunE = chat.RunE
}
