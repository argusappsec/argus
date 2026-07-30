---
title: GitHub channel
description: Automatic pull-request reviews, and talking to Argus right on the thread.
sidebar:
  order: 40
---

Argus connects to GitHub as a **GitHub App**: signed webhook events come in
on the HTTP front door at `/webhooks/github`, and Argus acts (clones, posts
reviews, replies) as the App installation — comments appear as `argus[bot]`.

## Setup

```sh
./argus codehost setup
```

The interactive setup walks you through connecting the App and writes both
config sections: the outbound identity under `codehosts:` and the inbound
webhook binding under `channels:` (see [Configuration](/guide/configuration/)).
Point the App's webhook URL at your daemon's front door:

```
https://argus.your-company.example/webhooks/github
```

## Automatic pull-request reviews

When a PR is **opened** or **synchronized** on an enrolled repo, Argus
reviews it — no CI wiring, no CLI verb. The review scans the whole checked-out
tree (not just the diff) and reports the findings that are relevant to the
PR.

Which installed repos get reviewed is gated by the channel config:

```yaml
channels:
  github:
    auto_enroll: false        # recommended: explicit opt-in
    enabled_repos:
      - my-org/payments-api
```

With `auto_enroll: true` (the current default when unset) every installed
repo is reviewed; prefer the allow-list — on a public repo, "anyone who can
open a PR" is the whole internet.

## Talking to Argus on a thread

Argus reads PR and issue comments on enrolled repos and answers when the
comment is addressed to it. Two forms work:

- **The bare name, opening the comment** *(canonical)*:
  `Argus, is this finding real?` — or your persona's name, even multi-word.
  Opening position is what separates talking *to* Argus from talking *about*
  it; "I think argus is wrong here" gets no reply.
- **The @-handle, anywhere** *(alias)*: `@argus` / `@<persona>` — kept
  because habit dies hard. Note that on github.com the `@argus` handle
  belongs to an unrelated real user who gets pinged; the bare name avoids
  that.

Who can talk: the commenter's GitHub login must resolve to a **Person** — one
human Argus recognizes, who may sign in from several places. Grant the identity
with:

```sh
argus user add alice
argus user grant alice --identity github:alice-gh
```

Comments from unknown logins — or not addressed to Argus — are **silently
ignored**: replying "contact your administrator" to every passer-by on a
public PR would be noise and an abuse surface.

## Security posture

An automatic review reads attacker-controlled content (the PR's code and
diff). Argus treats it accordingly:

- **Data, never instructions.** Reviewed code cannot direct the agent, and
  nothing it says is written back to the organization's knowledge base.
- **Confined file access.** Review tools and scanners operate inside the
  checkout under review, not the daemon's filesystem.
- **Controlled egress.** Org knowledge is loaded in full so the review stays
  sharp; confidentiality is enforced on what Argus *posts publicly*, which
  must be grounded in the reviewed tree itself.
