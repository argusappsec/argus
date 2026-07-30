---
title: LLM providers
description: What Argus requires from a model, and how to verify your own endpoint meets it.
sidebar:
  order: 30
---

An **LLM provider** is the model backend Argus generates through. A provider's
`type` names a **protocol, not a vendor**, and there are two:

| Type | What it speaks |
| --- | --- |
| `gemini` | Google's Gemini API |
| `openai-compatible` | The OpenAI chat-completions protocol — any server that implements it |

The second covers hosted services (OpenAI, OpenRouter, Groq, Together,
DeepSeek, Mistral, Cerebras) and local runtimes (Ollama, vLLM, LM Studio,
llama.cpp) alike, because they all speak the same wire format. A local runtime
is not a type of its own: it's a server that speaks this one, reached as a base
URL.

The word *compatible* is precise: Argus implements the protocol, and certifies
nobody's server. This page is the other half of that — what Argus needs from a
model, and how you check your own endpoint against it. For the configuration
keys themselves, see [Configuration](/guide/configuration/#llm-providers).

## What Argus requires from a model

Argus is an agent loop that lives on tool calls. It reads files, runs scanners,
files findings and finalizes a report **by calling tools** — a model that cannot
do that cannot do anything at all.

The requirements come in three groups, because they fail differently: some stop
Argus dead, some make it worse or more expensive, and some are things people
assume Argus needs and it doesn't.

### Hard requirements

Without these, Argus does not function.

**1. Function calling.** The loop is built on tool calls. Without them Argus
cannot read a file, run a scanner, or finalize a Report. This is not
degradation — it's total inertia: the model answers with prose, the loop sees no
tool call, treats that as a natural pause point, and ends the run having
reviewed nothing.

**2. Tool-call id correlation.** Argus returns each tool result carrying both
an **id** and a **name**. Gemini correlates results to calls by name; this
protocol correlates by **id**. It is the requirement nobody documents, and when
it breaks it breaks incomprehensibly — the model sees the wrong output attached
to the wrong call and reasons confidently from it.

Argus does what it can here. When a server emits empty or repeated ids, the
adapter **repairs them** rather than failing: it keeps every distinct id the
server did supply, synthesizes only what it must, deterministically from
position, and echoes the repaired ids back in the history the server sees. So a
single turn stays internally consistent even against a sloppy server.

What Argus cannot fix is the next turn. The ids it sends back in
`tool_call_id` are the repaired ones, which a server that emitted empty ids
never issued. A server that validates `tool_call_id` against ids of its own
rejects the follow-up request; one whose chat template ignores the field is
fine. **Symptom:** the first turn works, then the next request fails with the
server complaining about an unknown or invalid tool-call id — or, worse, the
model answers as if the tool results were never delivered.

**3. Context window.** SOUL — your organization's identity — and MEMORY — the
curated summary Argus keeps across sessions — enter the system prompt **in full
on every call**, and the tool declarations ride along on every call too. On top of
that sits a conversation that only grows: scanner output, file contents, diffs.
A small-context model dies on the first turn of a real Review.

**Floor: 32,768 tokens. Recommended: 128k or more.**

Here is the arithmetic, so you can redo it for your own model. Argus's fixed
per-call overhead — the assembled system prompt plus the full tool declaration
set — measures **8,953 bytes** (1,188 B of system prompt, 7,765 B across 17 tool
declarations). At an assumed **4 bytes per token**, that is roughly **2,240
tokens spent before the conversation has said a word** — about 7% of a 32k
window.

:::note
The measurement is bytes, not tokens, because converting to tokens needs a
tokenizer that differs per model family and that Argus deliberately does not
carry. The 4-bytes-per-token ratio is the usual rule of thumb for English and
code; substitute your model's real ratio if you know it. The figure is pinned by
a regression test, so it is kept honest rather than remembered.
:::

**8,953 B is a floor on the overhead, not a ceiling.** Three things push your
real figure above it:

- **Your SOUL and MEMORY.** The measurement uses a SOUL with every field set but
  deliberately short prose. Your own `SOUL.md` persona body and your `MEMORY.md`
  are **your bytes, on top, on every call** — and MEMORY grows as the curator
  appends to it.
- **A PR comment turn declares two more tools.** The GitHub channel adds
  `suppress_finding` and `rescope_review` for the turn that handles a comment.
- **The wire envelope.** The figure is measured on the provider-agnostic value,
  before a protocol's JSON framing adds its own few percent.

The remaining ~30k tokens are what a Review actually works in, and they go fast:
one scanner run plus a handful of file reads can fill them. 32k is the point
below which Argus stops being useful, not a comfortable size.

**4. System instruction honoured.** The system prompt is where SOUL and MEMORY
live — your organization's identity, stack, secret storage, compliance
obligations and severity rules. Argus sends it as a `system` message. Some local
chat templates silently drop or truncate that message.

**Argus raises no error.** Nothing fails, nothing is logged: the model simply
never sees your context, and produces competent, generic security output
instead of *your* security output. This is the most insidious entry in this
list precisely because it is silent.

**How to recognize it:** findings ignore your `severity_rules`; the agent
re-flags the placeholders your `secret_storage` setting exists to excuse; risk
calibration ignores your `risk_tolerance`; the agent doesn't know your company
name or sign itself with your persona name. If a Review reads like it was
written by a tool that has never heard of you, suspect the system prompt before
suspecting the model.

### Quality factors

These work, but worse or more expensively.

**5. Multiple tool calls per turn.** The loop handles N tool calls in one
response and batches every result back together. A model that emits only one
call per turn still works — it just needs one turn per action, burning them
against the agent's ceiling of **50 turns per message** (overridable with
`argus chat --max-turns`). On a large Review that ceiling is reachable, and
hitting it ends the run with a max-turns error instead of a Report.

**6. JSON Schema fidelity in tool parameters.** Argus passes each tool's schema
through **exactly as declared** — it makes no attempt to normalize or simplify
it for the model. A model that mangles nested objects or ignores `required`
fields calls tools with bad arguments, gets an error back, retries, and burns
turns doing it. Not fatal, but it converts turn budget into noise.

**7. Output ceiling.** A low server-side cap on output tokens truncates a long
Report mid-write. Set `max_output_tokens` on the provider entry to raise the
client-side request ceiling — see
[Configuration](/guide/configuration/#llm-providers).

It's worth being explicit about why that key exists: **the failure it prevents
is silent.** A truncated Report is not an error, it's a mutilated file — the
run succeeds, the report is written, and the last section just isn't there. You
cannot change a hosted server's default, so a client-side lever is the only fix
available to you.

### What Argus does not require

Stated so you don't rule out a model that would work fine:

- **Streaming.** Argus makes whole request/response turns.
- **Multimodal input.** Argus sends text. It reads source code, not images.
- **Embeddings.** There is no vector store anywhere in Argus.
- **JSON mode / structured-output modes.** **Argus uses tools, not constrained
  decoding.** Structured output arrives as tool-call arguments; a model needs no
  separate JSON or grammar mode.

## Verifying your endpoint

`argus doctor` probes **your** endpoint and **your** model, on **your**
machine, at the moment you configure it. Argus certifies nobody's server, so
this is where verification actually happens.

```sh
argus doctor
```

**Only `openai-compatible` providers are probed.** It is the type that points at
servers nobody has verified, and the only one whose protocol offers a listing to
ask. A `gemini` provider gets a row saying exactly that — an informational *not
probed*, never a failure: the Gemini API exposes no model listing to enumerate,
and a generation would spend tokens confirming tool calling that was never the
unknown. (A `type` Argus implements no provider for fails on that same row,
naming what to write instead.)

For a compatible endpoint, the probe reports on three things:

1. **The endpoint is reachable** and your key (if any) is accepted.
2. **The configured model id** is one the endpoint lists — so a typo surfaces
   before it costs you tokens. With one deliberate exception: an endpoint that
   lists **nothing** has not said your model is absent, so the row reports that
   the id **could not be verified** and carries on, rather than convicting a
   model id on no evidence and sending you to fix the one thing that isn't
   broken.
3. **The model actually emits a tool call**, verified with one minimal
   generation carrying a throwaway tool declaration.

The third is the one documentation alone can never cover. Plenty of servers
accept tool declarations and then ignore them — the common failure with small
local models — and the only way to know is to ask the model to call something
and see whether it does. A server that rejects tool declarations outright gets
that refusal reported as a plain statement that the model does not support tool
calling, rather than as a raw HTTP error from a server you didn't write.

This turns "Argus is broken" into "your model does not meet Argus's
requirements", which is the difference between a bug report and a configuration
fix.

### The probe requires `GET /models`

Steps 1 and 2 are **one request**. Reachability is established *by* listing
models, and that is the point: a single cheap GET settles three questions — the
endpoint answers, your key is accepted, your model id is one it serves —
**before a single token is spent.** A typo in a model id should cost you nothing
to find.

That ordering has a price, and it is better named here than discovered: **an
endpoint that serves `/chat/completions` but not `/models` fails the probe, and
fails it blockingly, even though Argus itself would run against it fine.** Argus
only ever posts to `/chat/completions`; the listing exists for verification.
Enumerate first, spend nothing is the order Argus deliberately settled on, and
this is its cost, paid knowingly. The failing row ends by asking you to report
the endpoint.

Please do. If yours is usable but unlistable:

- **`argus chat` and Reviews still work.** The row is a verdict about what could
  be *verified*, not about what Argus can do.
- **`argus doctor` exits non-zero**, so any CI step gated on it fails for that
  install.
- **Open an issue naming the server**, with the failing row — the probe's own
  hint asks you to. A named unlistable endpoint is worth more than a guess about
  whether any exist, and it reaches the maintainers by the same route as a
  compatibility report below.

## Compatibility reports

The table below is **community-fed**, and it is empty on purpose.

Verifying specific models and endpoints is explicitly not something this project
does: it would mean acquiring and re-testing models across a market that changes
weekly, and publishing a claim about your server that we cannot keep. A table of
plausible-looking rows nobody ran is exactly the claim `openai-compatible`
refuses to make. So it starts empty and grows from people who ran the probe.

| Endpoint | Model | Verified by | Argus version | Notes |
| --- | --- | --- | --- | --- |
| _(none yet — be the first)_ | | | | |

### Reporting a working setup

If `argus doctor` passes against your endpoint, you're one pull request away
from helping the next person:

1. Run `argus doctor` with your provider configured.
2. Open a pull request adding one row to the table above.
3. **Paste your `argus doctor` output in the pull-request body.** That output
   is the artifact — it's what makes the row a verified result rather than an
   assertion. Redact your API key and any private hostname.
4. In **Notes**, record anything that surprised you: a base URL whose `/v1`
   suffix differed, a `max_output_tokens` you had to set, a model that needed a
   larger context window than you expected.

Reports that Argus *doesn't* work are just as welcome — open an issue with the
same probe output. A known-bad model documented is more useful than a gap.

## Known risks and limits

**Prompts were written against Gemini — untested elsewhere.** SOUL and the
agent instructions were authored and tuned against Gemini models. Whether other
model families need different phrasing is **unanswered**, because answering it
means testing models this project does not have. It is a known risk, stated
rather than mitigated. If output quality on a non-Gemini model is worse than you
expected, prompt phrasing is a plausible cause and worth reporting.

**No retry, no backoff.** A failed request fails the turn. This matches the
Gemini provider, which has none either — it is the current bar, not a
regression against it. A flaky endpoint is felt directly.

**No streaming.** Responses arrive whole. On a slow local runtime, a long turn
looks like silence until it completes.

**Azure OpenAI is not supported.** It is close but not compatible: Azure uses a
different path shape (deployment-scoped, with an `api-version` query parameter)
and authenticates with an `api-key` header rather than
`Authorization: Bearer`. Pointing `openai-compatible` at an Azure endpoint will
not work.

**No spend control.** Argus reports token counts and bounds nothing. See
[Configuration](/guide/configuration/#cost-visibility).
