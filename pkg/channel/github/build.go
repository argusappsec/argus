package github

import (
	"fmt"
	"path/filepath"

	cdgithub "github.com/argusappsec/argus/pkg/codehost/github"
	"github.com/argusappsec/argus/pkg/config"
	"github.com/argusappsec/argus/pkg/daemon"
)

// The GitHub CodeHost must satisfy installationNoter so dispatch can seed the
// event's installation onto it (ADR 0015). NoteInstallation is kept off the
// neutral codehost.CodeHost seam — "installation" is a GitHub-ism (ADR 0010) —
// so this compile-time check guards against a silent fallback to per-repo
// resolution if the method's shape ever drifts.
var _ installationNoter = (*cdgithub.CodeHost)(nil)

// Build constructs the GitHub channel from its config section, resolving the
// App credentials (env() references → .env) and loading the PEM private key
// from the daemon host. It returns an error when the section is present but
// incomplete or the credentials cannot be loaded.
func Build(dc *daemon.Context, cfg config.GitHubConfig) (*Server, error) {
	minter, err := MintFromConfig(cfg)
	if err != nil {
		return nil, err
	}
	secret, err := cfg.ResolveWebhookSecret()
	if err != nil {
		return nil, fmt.Errorf("github: webhook secret: %w", err)
	}
	host := cdgithub.NewCodeHost(filepath.Join(dc.Home, "cache"), minter)
	return NewServer(dc, host, Options{
		Addr:          cfg.ListenAddr(),
		WebhookSecret: secret,
		AutoEnroll:    cfg.AutoEnrollEnabled(),
		EnabledRepos:  cfg.EnabledRepos,
		// persona.name lives at the top level of argus.yaml (not under github:),
		// so it reaches the channel via the shared daemon Context.
		PersonaName: dc.PersonaName,
	}), nil
}

// MintFromConfig builds the token minter from the App credentials in cfg. The
// installation is derived per event/repo (ADR 0015), never configured, so the
// minter carries only the App identity. Exported so `argus doctor` can verify
// the credentials without standing up the whole channel.
func MintFromConfig(cfg config.GitHubConfig) (*cdgithub.TokenMinter, error) {
	appID, err := cfg.ResolveAppID()
	if err != nil {
		return nil, fmt.Errorf("github: app id: %w", err)
	}
	key, err := cdgithub.LoadPrivateKeyFile(cfg.PrivateKeyPath)
	if err != nil {
		return nil, err
	}
	return cdgithub.NewTokenMinter(appID, key), nil
}
