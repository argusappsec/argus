# ADR 0021 — Cost controls are removed: token counts stay, the USD figure and the unwired caps go

**Status:** Accepted
**Date:** 2026-07-30
**Builds on:** [ADR 0020](0020-openai-compatible-provider.md)
**Amends:** [ADR 0002](0002-rbac-model.md),
[ADR 0004](0004-single-process-channel-goroutines.md),
[ADR 0018](0018-automatic-reviews-are-least-privilege.md) — each invokes a
budget cap that was never built

## Context

`pkg/budget`'s package comment promises three layers of cost protection. Only
one of them was ever connected to anything.

- **Per-call accounting** (`CostFor`) — promised to translate tokens into USD.
  Live, and feeds a display figure.
- **Per-session token cap** (`Session.Record`) — documented in the package
  comment as "the runaway-loop guard". **Dead code:** `budget.NewSession` is
  called nowhere outside `pkg/budget/budget_test.go`.
- **Per-day USD cap** (`Daily.Charge`) — promised a daemon-wide spend ceiling.
  **Dead code:** `budget.NewDaily` is called nowhere outside
  `pkg/budget/budget_test.go`.

The layer that *is* live is a **readout, not a control**. `CostFor` is called
from `pkg/daemon/session.go` and `cmd/init.go`, and the resulting number reaches
the user through the usage frame's `cost_usd` field
(`pkg/channel/uds/protocol.go`), the local TUI channel's status line and slash
readout (`pkg/channel/tui`), the chat client, and the `argus init` interview.
Nothing anywhere refuses a call because of it.

That figure depends on a hardcoded per-model price table, **duplicated in two
packages** — `defaultPricing()` in `cmd/runtime.go` and `defaultPricing()` in
`pkg/daemon/daemon.go`, five Gemini model ids each, the same numbers typed
twice. `CostFor` deliberately returns `0` for a model the table does not know,
so that an unpriced model never fails a run.

Under [ADR 0020](0020-openai-compatible-provider.md) that default becomes the
common case. An operator pointing Argus at a paid non-Gemini endpoint would be
shown a cost of **zero** for a Review that cost them real money. A false zero
is worse than no number: it is a number the user has no reason to distrust.

## Decision

**Delete `pkg/budget` in full and remove every USD figure. Token counts stay.**

The cost field goes from the usage frame on the wire, the local TUI channel's
display, the chat client, and the `argus init` interview. Both `defaultPricing`
tables go with it.

**The runaway-loop guard is not lost, because `pkg/budget` was never
providing it.** It exists and sits in the right place: the agent's turn
ceiling. `agent.Options.MaxTurns` defaults to `50` in `agent.New` when unset,
the loop in `Agent.Run` runs `for turn := 1; turn <= a.opts.MaxTurns; turn++`,
and exhausting it audits `session_end` with `reason: max_turns` and returns the
dedicated `agent.ErrMaxTurnsExceeded`. Chat clients can override it per
connection with `--max-turns`. Bounding turns is the better guard anyway: it
sits at the loop that can run away, and it needs no price table to work.

Its scope is worth stating plainly, because the deleted cap claimed a wider
one: the turn ceiling bounds **one `agent.Run`**, and a Session may produce
several runs in sequence — one per user message. A long-lived Session is
therefore bounded per message, not in aggregate. That is narrower than what
`Session.Record` described, and identical to what the daemon enforces today,
because `Session.Record` never ran. Nothing regresses; the documentation stops
overstating.

**Token counts survive** because they need nothing. They arrive in
`provider.Usage` on every response, are correct for every model on every
endpoint, and require no table to be maintained. An operator who wants a cost
figure has their provider's pricing page and an accurate token count.

This is **removal, not deferral.** A per-model USD table cannot be maintained
across arbitrary endpoints: the set of reachable models is open, prices change
per vendor on their own schedule, and the same model id costs different amounts
behind different gateways. There is no better table to wait for, so this is not
"deferred pending a better table". Reinstating a spend control is out of scope
**by decision**: a future spend control would be new work — metered against
real usage, at a layer that can actually refuse a call — not a restoration of
what is being deleted here.

Removing the USD readout is **release-coupled** to ADR 0020: shipping the
compatible Provider while a Gemini-only table is still consulted is what
displays the false zero. Deleting the dead caps is not coupled and may follow.

## Consequences

- Nobody loses a control, because the two caps never controlled anything and
  the third never refused a call. What users lose is a number, and the number
  was about to become wrong for most of them.
- **Three earlier ADRs lean on this phantom control** and are amended by this
  one. [ADR 0002](0002-rbac-model.md) lists "overrides budget" among the `admin`
  powers, and justifies letting `viewer` chat by calling the budget cap "the
  guardrail against runaway token spend, not the role boundary";
  [ADR 0004](0004-single-process-channel-goroutines.md) lists "its
  own per-session token budget" among what each Session owns;
  [ADR 0018](0018-automatic-reviews-are-least-privilege.md) offers "the global
  budget cap remains the hard spend backstop" as the counterweight to opt-in
  enrollment. None of those caps was ever constructed. **All three decisions
  stand** — `viewer` still chats, Sessions are still independent, enrollment is
  still opt-in — but their guardrail is the turn ceiling, and their spend claims
  should be read as amended here rather than as descriptions of the code.
- The glossary carries the same claims — budget gating for `viewer`, budget
  overrides for `admin`, "a budget counter" in the Session definition — and is
  corrected separately to match what the code enforces.
- This ADR does **not** add a spend control for `viewer`. Whether that Role
  should have one is a real question and a separate decision.
- The turn ceiling becomes the single documented answer to "what stops a
  runaway run?", so it needs to be discoverable in the guide rather than an
  implementation detail of `pkg/agent`.
- Reversible as code — the deleted package is one `git revert` away. It is
  recorded because it is precisely the kind of decision that gets re-argued
  from scratch: "Argus has no cost cap" reads like an oversight, and the
  documentation currently asserts the opposite.

## Alternatives considered

- **Keep the USD figure and widen the price table**, whether maintained by the
  maintainers or configured per Provider by the operator. Rejected on both
  variants for the reason above: no table is complete when any base URL is a
  valid endpoint, and an incomplete table reports zero rather than declining to
  answer. Pushing the table to the operator only moves the staleness.
- **Wire up the two dead caps instead of deleting them.** Rejected: the per-day
  USD cap needs the price table this ADR is removing, and the per-session token
  cap would sit at a worse layer than the turn ceiling — a token budget cannot
  distinguish a long legitimate Review from a loop, whereas a turn count can.
