package github

import (
	"fmt"
	"path/filepath"

	cdgithub "github.com/redcarbon-dev/argus/pkg/codehost/github"
	"github.com/redcarbon-dev/argus/pkg/config"
	"github.com/redcarbon-dev/argus/pkg/daemon"
)

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
	}), nil
}

// MintFromConfig builds the installation-token minter from the App
// credentials in cfg. Exported so `argus doctor` can verify a token can be
// minted without standing up the whole channel.
func MintFromConfig(cfg config.GitHubConfig) (*cdgithub.TokenMinter, error) {
	appID, err := cfg.ResolveAppID()
	if err != nil {
		return nil, fmt.Errorf("github: app id: %w", err)
	}
	installationID, err := cfg.ResolveInstallationID()
	if err != nil {
		return nil, fmt.Errorf("github: installation id: %w", err)
	}
	key, err := cdgithub.LoadPrivateKeyFile(cfg.PrivateKeyPath)
	if err != nil {
		return nil, err
	}
	return cdgithub.NewTokenMinter(appID, installationID, key), nil
}
