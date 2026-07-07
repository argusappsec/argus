package cmd

import (
	"fmt"
	"path/filepath"
	"sort"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/argusappsec/argus/pkg/auth"
)

// serviceCmd manages the services in ~/.argus/users.yaml (ADR 0003 / 0008). A
// Service is a non-human Principal authenticated by a shared secret: a
// github-app installation (one webhook secret, many repos) or a legacy
// per-repo ci-trigger. Like `argus user`, it edits the file directly.
func serviceCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "service",
		Short: "Manage services in the user table (~/.argus/users.yaml)",
		Long: "Manage Service Principals (ADR 0003/0008).\n\n" +
			"A Service is authenticated by a shared secret whose SHA-256 is stored.\n" +
			"Use --kind github-app for the GitHub App installation (pass the App's\n" +
			"webhook secret via --secret); omit --kind for a legacy per-repo\n" +
			"ci-trigger (a secret is generated and printed if you don't pass one).",
	}
	c.AddCommand(serviceAddCmd(), serviceListCmd(), serviceRemoveCmd())
	return c
}

func serviceStore(homeDir string) (*auth.Store, error) {
	home, err := resolveHome(homeDir)
	if err != nil {
		return nil, err
	}
	return auth.NewStore(filepath.Join(home, "users.yaml")), nil
}

func serviceAddCmd() *cobra.Command {
	var homeDir, role, kind, repo, secret string
	c := &cobra.Command{
		Use:   "add <id>",
		Short: "Add a service",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := serviceStore(homeDir)
			if err != nil {
				return err
			}

			switch kind {
			case "github-app":
				if secret == "" {
					return fmt.Errorf("--secret is required for --kind github-app (it must equal the App's webhook secret)")
				}
				if repo != "" {
					return fmt.Errorf("--repo is not used for a github-app service (its repos come from the installation)")
				}
			case "":
				if repo == "" {
					return fmt.Errorf("--repo is required for a ci-trigger service")
				}
			default:
				return fmt.Errorf("unknown --kind %q (want github-app or empty for ci-trigger)", kind)
			}

			generated := false
			if secret == "" {
				secret, err = randomHex(24)
				if err != nil {
					return err
				}
				generated = true
			}

			svc := auth.Service{
				ID:           args[0],
				Role:         auth.Role(role),
				Kind:         kind,
				Repo:         repo,
				SecretSHA256: auth.SHA256Hex(secret),
			}
			if err := store.AddService(svc); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "added service %q (role %s%s)\n",
				svc.ID, svc.Role, kindSuffix(kind))
			if generated {
				fmt.Fprintf(cmd.OutOrStdout(), "generated secret — store it now, it is not recoverable:\n\n  %s\n\n", secret)
			}
			return nil
		},
	}
	c.Flags().StringVar(&homeDir, "home", "", "Override ~/.argus home directory")
	c.Flags().StringVar(&role, "role", string(auth.RoleCITrigger), "Role: ci-trigger|mirror-read")
	c.Flags().StringVar(&kind, "kind", "", "Service kind: github-app (or empty for a per-repo ci-trigger)")
	c.Flags().StringVar(&repo, "repo", "", "Repo a ci-trigger is bound to, e.g. github.com/owner/repo")
	c.Flags().StringVar(&secret, "secret", "", "Shared secret (its SHA-256 is stored). github-app: the App webhook secret")
	return c
}

func serviceListCmd() *cobra.Command {
	var homeDir string
	c := &cobra.Command{
		Use:     "ls",
		Aliases: []string{"list"},
		Short:   "List services",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := serviceStore(homeDir)
			if err != nil {
				return err
			}
			services, err := store.Services()
			if err != nil {
				return err
			}
			if len(services) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "No services. Add one with `argus service add`.")
				return nil
			}
			sort.Slice(services, func(i, j int) bool { return services[i].ID < services[j].ID })
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tROLE\tKIND\tREPO")
			for _, s := range services {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
					s.ID, s.Role, dashIfEmpty(s.Kind), dashIfEmpty(s.Repo))
			}
			return w.Flush()
		},
	}
	c.Flags().StringVar(&homeDir, "home", "", "Override ~/.argus home directory")
	return c
}

func serviceRemoveCmd() *cobra.Command {
	var homeDir string
	c := &cobra.Command{
		Use:     "rm <id>",
		Aliases: []string{"remove"},
		Short:   "Remove a service",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := serviceStore(homeDir)
			if err != nil {
				return err
			}
			if err := store.RemoveService(args[0]); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "removed service %q\n", args[0])
			return nil
		},
	}
	c.Flags().StringVar(&homeDir, "home", "", "Override ~/.argus home directory")
	return c
}

func kindSuffix(kind string) string {
	if kind == "" {
		return ""
	}
	return ", kind " + kind
}
