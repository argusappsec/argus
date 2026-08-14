package daemon

import (
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/argusappsec/argus/pkg/config"
	"github.com/argusappsec/argus/pkg/deployment"
)

// This file derives the Deployment shape from the daemon's configuration and
// says what it forbids. The vocabulary itself — what a Toolbox and a Colleague
// are — lives in pkg/deployment, which the Channels and `argus doctor` read
// without depending on the daemon. Everything downstream reads Context.Shape.

// ShapeOf derives the Deployment shape from a daemon's configuration: a
// Colleague as soon as one Provider is reachable, a Toolbox otherwise. This is
// the only place the question is asked.
//
// The no-`providers:` environment-variable fallback counts as a Provider, so an
// install that exported a key and never ran `argus init` reasons exactly as it
// did before instead of silently degrading. That fallback reads the process
// environment, which is why the daemon's .env must be applied before this is
// asked (Build does).
func ShapeOf(cfg *config.Config) deployment.Shape {
	if cfg != nil && len(cfg.Providers) > 0 {
		return deployment.Colleague
	}
	if hasFallbackAPIKey() {
		return deployment.Colleague
	}
	return deployment.Toolbox
}

// ErrNoReasoning is what a capability that needs Argus's own agent loop returns
// in a Toolbox. It is an explanation rather than a failure code because every
// channel that can hit it shows the text to a person or to their AI: the wrong
// answer here is not an error, it is an obscure one.
var ErrNoReasoning = errors.New(
	"argus is running as a Toolbox: no LLM Provider is configured, so it cannot reason on its own behalf — " +
		"review, consult and chat all need one. Configure a provider under `providers:` in argus.yaml " +
		"(`argus init`) to run as a Colleague. Meanwhile the scanners, the organization's knowledge and the " +
		"Skills are served over MCP, for an AI that reasons on your machine to drive")

// validateChannelsForShape refuses at startup a configured Channel that cannot
// function in this Deployment shape. It sits next to config.Validate for the
// same reason: a misconfigured integration surface fails loudly rather than
// becoming a silently dead channel.
//
// The TUI Channel is deliberately never refused — possession of the socket is
// how an operator administers the daemon (ADR 0007), so a Toolbox has to accept
// the connection; a conversational turn requested there answers with
// ErrNoReasoning instead.
func validateChannelsForShape(cfg *config.Config, shape deployment.Shape) error {
	if cfg == nil || !shape.IsToolbox() {
		return nil
	}
	// Sorted: map iteration would name a different channel on every run when
	// two of them are wrong.
	for _, name := range slices.Sorted(maps.Keys(cfg.Channels)) {
		ch := cfg.Channels[name]
		reason := channelNeedsReasoning(ch)
		if reason == "" {
			continue
		}
		return fmt.Errorf("config: channel %q (%s) cannot run in a Toolbox: %s, and no LLM Provider is configured. "+
			"Configure one under `providers:` (`argus init`), or remove the channel", name, ch.Type, reason)
	}
	return nil
}

// channelNeedsReasoning returns why a configured Channel can only function with
// a Provider behind it, or "" when it can work without one. The reason travels
// into the operator's error message.
//
// The Slack Channel belongs in this switch too: every event on it is a
// conversational turn with Argus's own agent. It is absent only because the
// Channel is not implemented, so `type: slack` is refused by config.Validate as
// an unknown type before this is reached; it moves here on the day the Channel
// lands, and TestBuild_ToolboxRefusesASlackChannel fails on that day to say so.
func channelNeedsReasoning(ch config.ChannelConfig) string {
	switch ch.Type {
	case config.ChannelTypeGitHub:
		// Only the automatic review path. It starts Argus's agent loop on an
		// event nobody asked for, which is precisely what a Toolbox cannot do
		// (ADR 0023). A github channel that reviews nothing automatically still
		// carries the comment path, and a comment turn is refused per turn the
		// way the TUI's is.
		if ch.AutoEnrollEnabled() || len(ch.EnabledRepos) > 0 {
			return "its automatic pull-request review runs Argus's own agent loop"
		}
	}
	return ""
}
