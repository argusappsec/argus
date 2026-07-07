package cmd

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/argusappsec/argus/pkg/auth"
)

// userCmd manages the persons in ~/.argus/users.yaml (ADR 0003). It writes the
// file directly — it does NOT go through the running daemon, so the attack
// surface for "add a backdoor admin" stays at "have shell access on the host".
func userCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "user",
		Short: "Manage persons in the user table (~/.argus/users.yaml)",
		Long: "Manage the Persons that can act on Argus (ADR 0003).\n\n" +
			"Persons own Identities (slack:…, github:…, mcp-token) and one Role\n" +
			"(admin|analyst|viewer). Commands edit ~/.argus/users.yaml directly;\n" +
			"they never go through the daemon.",
	}
	c.AddCommand(userAddCmd(), userListCmd(), userRemoveCmd(), userGrantCmd(), userMCPTokenCmd())
	return c
}

func userStore(homeDir string) (*auth.Store, error) {
	home, err := resolveHome(homeDir)
	if err != nil {
		return nil, err
	}
	return auth.NewStore(filepath.Join(home, "users.yaml")), nil
}

// collectIdentities merges the explicit --identity values with the --github
// and --slack shortcuts into one ordered, de-duplicated list.
func collectIdentities(identities []string, github, slack string) []string {
	out := append([]string{}, identities...)
	if github != "" {
		out = append(out, "github:"+github)
	}
	if slack != "" {
		out = append(out, "slack:"+slack)
	}
	seen := map[string]bool{}
	dedup := out[:0]
	for _, id := range out {
		if !seen[id] {
			seen[id] = true
			dedup = append(dedup, id)
		}
	}
	return dedup
}

func userAddCmd() *cobra.Command {
	var homeDir, role, email, github, slack string
	var identities []string
	c := &cobra.Command{
		Use:   "add <id>",
		Short: "Add a person",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := userStore(homeDir)
			if err != nil {
				return err
			}
			p := auth.Person{
				ID:         args[0],
				Email:      email,
				Role:       auth.Role(role),
				Identities: collectIdentities(identities, github, slack),
			}
			if err := store.AddPerson(p); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "added person %q (role %s)\n", p.ID, p.Role)
			return nil
		},
	}
	c.Flags().StringVar(&homeDir, "home", "", "Override ~/.argus home directory")
	c.Flags().StringVar(&role, "role", "", "Role: admin|analyst|viewer (required)")
	c.Flags().StringVar(&email, "email", "", "Email address")
	c.Flags().StringArrayVar(&identities, "identity", nil, "Identity, e.g. mcp:… (repeatable)")
	c.Flags().StringVar(&github, "github", "", "GitHub login (shortcut for --identity github:<login>)")
	c.Flags().StringVar(&slack, "slack", "", "Slack user id (shortcut for --identity slack:<id>)")
	_ = c.MarkFlagRequired("role")
	return c
}

func userGrantCmd() *cobra.Command {
	var homeDir, github, slack string
	var identities []string
	c := &cobra.Command{
		Use:   "grant <id>",
		Short: "Grant additional identities to an existing person",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := userStore(homeDir)
			if err != nil {
				return err
			}
			ids := collectIdentities(identities, github, slack)
			if len(ids) == 0 {
				return fmt.Errorf("nothing to grant: pass --identity, --github or --slack")
			}
			for _, id := range ids {
				if err := store.AddIdentity(args[0], id); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "granted %s to %q\n", id, args[0])
			}
			return nil
		},
	}
	c.Flags().StringVar(&homeDir, "home", "", "Override ~/.argus home directory")
	c.Flags().StringArrayVar(&identities, "identity", nil, "Identity to grant (repeatable)")
	c.Flags().StringVar(&github, "github", "", "GitHub login (shortcut for github:<login>)")
	c.Flags().StringVar(&slack, "slack", "", "Slack user id (shortcut for slack:<id>)")
	return c
}

func userListCmd() *cobra.Command {
	var homeDir string
	c := &cobra.Command{
		Use:     "ls",
		Aliases: []string{"list"},
		Short:   "List persons",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := userStore(homeDir)
			if err != nil {
				return err
			}
			persons, err := store.Persons()
			if err != nil {
				return err
			}
			if len(persons) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "No persons. Add one with `argus user add`.")
				return nil
			}
			sort.Slice(persons, func(i, j int) bool { return persons[i].ID < persons[j].ID })
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tROLE\tEMAIL\tIDENTITIES\tMCP-TOKENS")
			for _, p := range persons {
				names := make([]string, 0, len(p.MCPTokens))
				for _, t := range p.MCPTokens {
					names = append(names, t.Name)
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
					p.ID, p.Role, dashIfEmpty(p.Email),
					dashIfEmpty(strings.Join(p.Identities, ",")),
					dashIfEmpty(strings.Join(names, ",")))
			}
			return w.Flush()
		},
	}
	c.Flags().StringVar(&homeDir, "home", "", "Override ~/.argus home directory")
	return c
}

func userRemoveCmd() *cobra.Command {
	var homeDir string
	c := &cobra.Command{
		Use:     "rm <id>",
		Aliases: []string{"remove"},
		Short:   "Remove a person",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := userStore(homeDir)
			if err != nil {
				return err
			}
			if err := store.RemovePerson(args[0]); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "removed person %q\n", args[0])
			return nil
		},
	}
	c.Flags().StringVar(&homeDir, "home", "", "Override ~/.argus home directory")
	return c
}

func userMCPTokenCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "mcp-token <id>",
		Short: "Create or revoke a person's MCP tokens",
	}
	c.AddCommand(userMCPTokenCreateCmd(), userMCPTokenRevokeCmd())
	return c
}

func userMCPTokenCreateCmd() *cobra.Command {
	var homeDir, name string
	c := &cobra.Command{
		Use:   "create <id>",
		Short: "Create an MCP token (prints the cleartext once, stores only its hash)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := userStore(homeDir)
			if err != nil {
				return err
			}
			token, err := randomHex(24)
			if err != nil {
				return err
			}
			if err := store.AddMCPToken(args[0], name, auth.SHA256Hex(token)); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "created token %q for %q. Store it now — it is not recoverable:\n\n  %s\n\n", name, args[0], token)
			fmt.Fprintf(cmd.OutOrStdout(), "Use it as the bearer token; the identity resolves to mcp:<token-hash>.\n")
			return nil
		},
	}
	c.Flags().StringVar(&homeDir, "home", "", "Override ~/.argus home directory")
	c.Flags().StringVar(&name, "name", "", "Friendly token name (required)")
	_ = c.MarkFlagRequired("name")
	return c
}

func userMCPTokenRevokeCmd() *cobra.Command {
	var homeDir, name string
	c := &cobra.Command{
		Use:   "revoke <id>",
		Short: "Revoke a person's MCP token by name",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := userStore(homeDir)
			if err != nil {
				return err
			}
			if err := store.RemoveMCPToken(args[0], name); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "revoked token %q from %q\n", name, args[0])
			return nil
		},
	}
	c.Flags().StringVar(&homeDir, "home", "", "Override ~/.argus home directory")
	c.Flags().StringVar(&name, "name", "", "Token name to revoke (required)")
	_ = c.MarkFlagRequired("name")
	return c
}

// randomHex returns n cryptographically-random bytes as a hex string.
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate random: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func dashIfEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
