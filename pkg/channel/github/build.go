package github

import (
	"fmt"

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

// Build constructs the GitHub channel around the shared authenticated CodeHost
// (dc.CodeHost, built once from codehosts: — ADR 0015): the channel clones and
// calls the API through the same client the chat review tool and the MCP repo
// target use, so a private repo works from every trigger. The webhook secret
// and enrolment policy come from the github channel config. It returns an error
// when the codehost is absent or the secret cannot be resolved.
func Build(dc *daemon.Context, ch config.ChannelConfig) (*Server, error) {
	if dc.CodeHost == nil {
		return nil, fmt.Errorf("github: channel requires a github codehost under `codehosts:`")
	}
	secret, err := ch.ResolveWebhookSecret()
	if err != nil {
		return nil, fmt.Errorf("github: webhook secret: %w", err)
	}
	return NewServer(dc, dc.CodeHost, Options{
		WebhookSecret: secret,
		AutoEnroll:    ch.AutoEnrollEnabled(),
		EnabledRepos:  ch.EnabledRepos,
		// persona.name lives at the top level of argus.yaml (not under a
		// channel), so it reaches the channel via the shared daemon Context.
		PersonaName: dc.PersonaName,
	}), nil
}
