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

// Build constructs the GitHub channel from the config v2 sections: the outbound
// App identity comes from the github codehost, the webhook secret and enrolment
// policy from the github channel. env() references resolve from .env and the PEM
// private key is loaded from the daemon host. It returns an error when the
// credentials are incomplete or cannot be loaded.
func Build(dc *daemon.Context, host config.CodeHostConfig, ch config.ChannelConfig) (*Server, error) {
	minter, err := MintFromConfig(host)
	if err != nil {
		return nil, err
	}
	secret, err := ch.ResolveWebhookSecret()
	if err != nil {
		return nil, fmt.Errorf("github: webhook secret: %w", err)
	}
	cdhost := cdgithub.NewCodeHost(filepath.Join(dc.Home, "cache"), minter)
	return NewServer(dc, cdhost, Options{
		WebhookSecret: secret,
		AutoEnroll:    ch.AutoEnrollEnabled(),
		EnabledRepos:  ch.EnabledRepos,
		// persona.name lives at the top level of argus.yaml (not under a
		// channel), so it reaches the channel via the shared daemon Context.
		PersonaName: dc.PersonaName,
	}), nil
}

// MintFromConfig builds the token minter from the codehost's App credentials.
// The installation is derived per event/repo (ADR 0015), never configured, so
// the minter carries only the App identity. Exported so `argus doctor` can
// verify the credentials without standing up the whole channel.
func MintFromConfig(host config.CodeHostConfig) (*cdgithub.TokenMinter, error) {
	appID, err := host.ResolveAppID()
	if err != nil {
		return nil, fmt.Errorf("github: app id: %w", err)
	}
	key, err := cdgithub.LoadPrivateKeyFile(host.PrivateKeyPath)
	if err != nil {
		return nil, err
	}
	return cdgithub.NewTokenMinter(appID, key), nil
}
