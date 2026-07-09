package github

import (
	"fmt"

	"github.com/argusappsec/argus/pkg/config"
)

// BuildCodeHost constructs the authenticated GitHub CodeHost from a codehost's
// App credentials (ADR 0015). Clones are cached under cacheRoot; the acting
// installation is derived per event/repo, never configured, so the minter
// carries only the App identity. This is the single client the daemon builds
// once and shares with every consumer (the GitHub channel, the chat review
// tool, the MCP repo target).
func BuildCodeHost(cacheRoot string, host config.CodeHostConfig) (*CodeHost, error) {
	minter, err := MintFromConfig(host)
	if err != nil {
		return nil, err
	}
	return NewCodeHost(cacheRoot, minter), nil
}

// MintFromConfig builds the token minter from the codehost's App credentials.
// env() references resolve from .env and the PEM private key is loaded from the
// daemon host. Exported so `argus doctor` can verify the credentials without
// standing up the whole client.
func MintFromConfig(host config.CodeHostConfig) (*TokenMinter, error) {
	appID, err := host.ResolveAppID()
	if err != nil {
		return nil, fmt.Errorf("github: app id: %w", err)
	}
	key, err := LoadPrivateKeyFile(host.PrivateKeyPath)
	if err != nil {
		return nil, err
	}
	return NewTokenMinter(appID, key), nil
}
