# ADR 0020 — The Provider type names a protocol; its client is hand-written; no server is certified

**Status:** Accepted
**Date:** 2026-07-30
**Builds on:** [ADR 0004](0004-single-process-channel-goroutines.md),
[ADR 0010](0010-codehost-interface-one-implementation.md)

## Context

Argus generates through exactly one LLM: Gemini. Anyone evaluating Argus must
first obtain a Google API key, and anyone whose organization standardized on a
different vendor — or who wants code analysis to stay on hardware they own —
cannot run Argus at all. A security tool that reads your source tree is
precisely the software an organization wants to point at an endpoint it
controls, and today the answer to "can I try this with what I already have?"
is no.

The configuration surface already pretends otherwise. `ProviderConfig` carries
a `type` field, and the struct's doc comment reserves `openai`, `anthropic` and
`ollama` — but **nothing selects an implementation from it**. The only code
that reads `Type` is `matchesProvider` in `pkg/config`, which uses it as one
more string to match a model-id prefix against; construction ignores it
entirely. `providerFactory` in `pkg/daemon/daemon.go` resolves an API key and
then calls `gemini.New` unconditionally, and `argus init` calls `gemini.New`
directly too.

So writing `type: openai` does not fail where the mistake is. A non-Gemini
model id matches no provider entry, so config resolution reports "no provider
configured for model …"; and when `GEMINI_API_KEY` happens to be exported the
daemon's fallback builds a **Gemini** client for a model Gemini has never heard
of, which fails later and elsewhere. Either way the error points the user at
the wrong problem.

That the second Provider should exist is not the interesting question. The
interesting questions are what the Provider type is **called**, what the client
is **built from**, and what Argus **promises** about the server on the other
end. All three answers land in users' `argus.yaml` files and in the project's
public compatibility claims, which makes them expensive to walk back and worth
recording together: they are one argument, not three notes.

## Decision

**Argus implements the OpenAI-compatible chat-completions protocol as its
second Provider: the type is named after the protocol, the client is written by
hand, and no server is certified.**

Construction moves behind a factory in `pkg/provider` that takes a `Spec` (the
Provider type, API key, base URL, model) and returns the matching
`provider.Provider`, or an error naming the supported types. `Spec` is owned by
`pkg/provider`, not `pkg/config`: the Provider abstraction stays ignorant of
the `argus.yaml` file format, and the caller maps config into `Spec`. Both
construction sites — the daemon's factory and the `argus init` interview — go
through it, and neither imports a concrete implementation any more. This keeps
[ADR 0004](0004-single-process-channel-goroutines.md)'s contract intact:
Channels never construct a Provider, they receive a `DaemonContext`, and the
injected per-Session provider constructor on it stays the boundary at which
Sessions acquire a Provider.

`provider.Provider` itself is **unchanged** by this work. That is worth noting
against [ADR 0010](0010-codehost-interface-one-implementation.md), which
predicted that a second implementation would both arrive *and* reshape the
interface it was inferred from. For CodeHost that prediction still stands
untested. For the one-method `Provider` interface it did not come true — a
second implementation slotted in behind it without moving a seam, and what had
to be built was the factory that chooses between them.

### The type names a protocol: `openai-compatible`

The type value is `openai-compatible`, not `openai`. The name states what
Argus implements — a wire protocol — rather than implying a relationship with
a vendor, and the word *compatible* carries the "we do not certify your
server" posture into the user's configuration file itself. `url` is optional
and defaults to the OpenAI public endpoint, so pointing at OpenAI needs no URL.

**`ollama` is removed from the reserved-type list.** Ollama is not a Provider
type: it is a server that speaks this protocol, configured as a base URL like
any other. The current reserved list conflates vendors (`anthropic`) with
local runtimes (`ollama`) as though they belonged to the same category as
`gemini`. Under this decision there is one category — the protocol — and
hosted aggregators, hosted inference services and local runtimes alike are
endpoints of it, distinguished by a URL rather than by a type.

### The client is hand-written

The adapter is `net/http` plus `encoding/json`: `POST /chat/completions`
carrying model, messages and tool declarations, decoding message content, tool
calls and token usage; plus `GET /models` for the probe.

The decisive reason is **tolerance, not size**. Argus talks to servers that are
*approximately* OpenAI. A strictly typed SDK written for the real OpenAI
rejects responses that compatible servers legitimately return — an absent
`usage` object, a non-standard `finish_reason`, tool-call ids formed their own
way. A lenient hand-written decoder accepts them. Tolerance is the feature
here, not a compromise, which is why "the SDK is only a dependency away" does
not answer the question.

Two supporting reasons: recent versions of the official SDK steer towards the
Responses API, which compatible servers do not implement, so Argus would be
pinned against the library's direction indefinitely; and every dependency is
supply-chain surface in a product that sells security.

No retry or backoff logic. The Gemini Provider has none, so this matches the
current bar rather than regressing from it.

### No server is certified

Verification happens on the **user's machine, against the user's model, at the
moment they configure it** — a live capability probe in `argus doctor`,
injected as a function field exactly like the existing GitHub token-minting and
front-door probes. It enumerates `/models` to establish reachability, key
validity and existence of the configured model id before spending tokens, then
performs a minimal generation carrying one throwaway tool declaration and
asserts a tool call comes back. Servers that reject tool declarations outright
get that client error translated into a plain statement that the model does not
support tool calling; servers that accept tool declarations and then ignore
them — the common local small-model failure — are caught by the generation
step, which is the case documentation alone cannot cover.

Around the probe sits a documented **Requirements contract** stating what
Argus needs (function calling, tool-call id correlation, a context-window
floor, a system instruction that is honoured), what merely degrades, and what
Argus explicitly does not need. The compatibility table in the guide is
**community-fed**: the artifact a contributor pastes into a pull request is
their `argus doctor` output.

This is what makes "compatible" an honest promise rather than a disclaimer.
The project makes no claim it has not verified, and every new user who runs the
probe is a potential contributor.

## Consequences

- The `type` field becomes load-bearing: it now selects an implementation, and
  an unknown value fails with an error naming the supported types instead of
  landing the user in a Gemini client. Existing Gemini configurations keep
  working untouched.
- `openai-compatible` is a longer string than `openai` and users will
  occasionally write the shorter one. That cost is paid once, at configuration
  time, against a name that keeps telling the truth for the life of the file.
- Argus owns the wire format. When a server returns something new and strange,
  the fix is a few lines in a decoder we control rather than an upstream issue
  and a version bump — but it is also our bug, and breadth of endpoint
  coverage is now our maintenance burden.
- Support questions shift shape. "Argus is broken" becomes "your model does not
  meet Argus's requirements", which is the difference between a bug report and
  a configuration fix — but only for users who run `argus doctor`, so the guide
  has to send them there.
- The tolerance decisions become executable rather than aspirational: each
  sloppy server behaviour the design accepts gets a case against an `httptest`
  stand-in endpoint (absent `usage`, non-standard `finish_reason`, empty or
  duplicated tool-call ids, several tool calls in one response, a client error
  in response to tool declarations).
- **Known risk (untested):** SOUL and the agent instructions were written
  against Gemini. Whether other model families need different phrasing is
  unanswerable without testing models the project does not have, which is
  explicitly not being done here. It is recorded as a known risk in the
  Requirements documentation rather than mitigated.

## Alternatives considered

- **The official OpenAI Go SDK.** Rejected for the tolerance reason above: the
  servers this work exists to reach are the ones a strict client rejects.
  Secondarily, the endpoint surface Argus needs is two calls, so the SDK buys
  little in exchange for its Responses-API drift and its place in a security
  product's dependency tree.
- **`type: openai`.** Rejected: shorter to type, and wrong. It implies a vendor
  relationship Argus does not have and reads as a lie in the config of anyone
  pointing at Groq or their own GPU. The name is the cheapest place to be
  honest about what is implemented.
- **Keeping `ollama` as a Provider type.** Rejected: it would mean one adapter
  registered under several names, and it teaches users a false model in which
  every new runtime needs Argus to add a type. A local runtime is a base URL.
- **A maintainer-tested compatibility matrix.** Rejected: it commits the
  maintainers to acquiring and re-testing models across a market that changes
  weekly, it is stale the day it is published, and it makes a promise about the
  user's server that the project cannot keep. Verification on the user's own
  machine is cheaper, more truthful, and turns users into contributors.
- **Waiting for a native Anthropic Provider instead.** Rejected as a
  substitute: Claude models are reachable through OpenAI-compatible gateways
  today, so one adapter unlocks them alongside the rest of the market. A
  first-party adapter remains a separate decision.
