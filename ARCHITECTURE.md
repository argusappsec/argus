# Argus — Architecture Spec

> Documento di partenza per il progetto **Argus**, un agent framework AI focalizzato su cyber security, costruito come progetto di studio per imparare a sviluppare agenti autonomi.
>
> Riferimenti architetturali: [WildGecu](https://github.com/ludusrusso/wildgecu) (Go, file-based, soul/memory/skills) e [OpenClaw](https://github.com/openclaw/openclaw) (TypeScript, multi-channel gateway). WildGecu è lo specchio principale.

---

## 1. Obiettivo e filosofia

**Obiettivo primario**: imparare come si costruisce un agent framework agentic da zero, applicato a un dominio reale ad alto valore (cyber security).

**Obiettivo secondario**: produrre un tool effettivamente utile per identificare e tracciare problemi di sicurezza in progetti software aziendali, generando report che evolvono nel tempo (utile a un CISO).

**Vincoli durevoli**:
- L'agente **NON modifica codice**. Identifica problemi, li descrive, suggerisce remediation. Il fix è umano.
- File-based state by default. Niente DB fino a quando non è strettamente necessario (post-v1.0).
- Safeguard non bypassabili per le parti pericolose (black-box pentesting).
- Pedagogicamente trasparente: ogni componente deve insegnare un concetto agentic specifico.

---

## 2. Strategia generale

| Asse | Scelta | Razionale |
|------|--------|-----------|
| Strategia di partenza | Framework custom da zero | Massimo apprendimento sui fondamentali. WildGecu come reference, non come dipendenza. |
| Linguaggio | Go (1.26+, mise per toolchain) | Specchio diretto di WildGecu, single-binary daemon-friendly, concorrenza nativa per subagent paralleli. |
| Provider LLM iniziale | Gemini via `google.golang.org/genai` | Choice utente. Provider interface astratta fin da v0.1 per swap futuro. |
| Tool calling | Native Function Calling Gemini | Standard di fatto, parsing pulito, schema validation a carico del provider. |
| Storage | File-based (markdown + YAML frontmatter) | Coerente con WildGecu, version-control friendly, niente dipendenze. |
| Sandboxing | No in v0.1 (tool fidati su repo proprio). Docker obbligatorio in v1.0 per pentesting. | Complessità giusta al momento giusto. |

---

## 3. Roadmap ad anelli concentrici

Ogni anello aggiunge **un solo concetto agentic nuovo** da imparare. Si parte dal cuore (agent loop) e si espande verso l'esterno (canali, integrazioni, autonomia).

### v0.1 — Agent loop monolitico
**Concetto pedagogico**: tool calling nativo, prompt assembly, stop conditions.

- Comando: `argus review <github-repo-url>`
- Input: 1 repo GitHub
- Auth GitHub: PAT fine-grained in `~/.argus/.env`
- Strategia codice: `git clone --depth=1` in temp dir, cache per commit SHA
- 1 skill hardcoded in Go: **white-box security review** (paradigma ibrido)
- Tool disponibili all'agente:
  - `list_files(path)`
  - `read_file(path, line_start?, line_end?)`
  - `grep(pattern, path)`
  - `run_semgrep(path, rules?)`
  - `run_gitleaks(path)`
  - `add_finding(severity, file, line, rule_id, snippet, description, remediation)`
  - `finalize_report(summary)`
- Tool calling: native `FunctionDeclaration` Gemini
- Sandbox: nessuno, `os/exec` con context timeout
- Stop conditions:
  - L'agente chiama `finalize_report` → fine naturale
  - Safety net: max 50 turn, max ~200k token cumulativi, timeout wall-clock 10 min
- UI: CLI streaming stdout
- Output: report markdown con frontmatter YAML in `~/.argus/reports/<repo>/<sha>.md`
- Finding ID stabile: `hash(rule_id + normalized_code_snippet)` (sopravvive a refactor di righe/file)

### v0.2 — Soul, Memory, Context
**Concetto pedagogico**: identità, knowledge injection, context economy.

- `SOUL.md` — markdown + frontmatter, generato da `argus init` (bootstrap interview, come WildGecu). Contiene: azienda, industry, compliance regime, risk tolerance, escalation contact, repo monitorati, persona/tone.
- `CONTEXT/` — cartella di markdown letta on-demand dall'agente con tool `list_context()` e `read_context(name)`. Esempi: `architecture.md`, `threat-model.md`, `compliance-soc2.md`, `known-fps.md`, `escalation.md`.
- `MEMORY.md` — curato da un **memory-curator subagent** a fine sessione (anche se la spec subagent completa arriva in v0.3, questo è il primo spawn ephemeral implementato).
- Vector store / embeddings: rinviati a post-v0.7 quando il CONTEXT supererà i 100KB.

### v0.3 — Skill system + Subagent ephemeral
**Concetto pedagogico**: delega, isolamento contesto, riusabilità.

- Skill loader markdown: `~/.argus/skills/<name>/SKILL.md` con frontmatter YAML (description, model, tools, when_to_use). Lazy-loaded come WildGecu.
- 2-3 skill markdown oltre alla white-box review (es. `secret-scan`, `dep-audit`, `threat-model`).
- Subagent ephemeral via tool `spawn_agent(name, task, model?, tools?)`:
  - Context isolato dal parent
  - Tool subset (e.g. secret-scanner ha solo read_file + run_gitleaks)
  - Model override opzionale (parent gemini-pro, child gemini-flash)
  - Ritorna stringa (o JSON) al parent
- Ogni tipo di subagent ha **proprio SOUL** in `~/.argus/subagents/<name>/SOUL.md`.

### v0.4 — Daemon, cron, HTML renderer
**Concetto pedagogico**: stato persistente, scheduling, separazione data/view (two-layer reporting).

- `argus start` daemon background. IPC via Unix socket. Lifecycle: `start`/`stop`/`restart`/`status`/`logs`/`health`.
- Scheduler in-process: `gocron`. Comandi: `argus cron ls/add/rm`.
- HTML renderer pattern **two-layer**:
  - L'agente continua a produrre markdown + frontmatter YAML
  - Pacchetto Go `pkg/render/` legge i report e produce HTML statico (`html/template` + Chart.js per trend)
  - `argus serve` apre HTTP locale (es. :8080) con dashboard cross-repo, trend, diff side-by-side, filtri severity/category
  - Output statico pubblicabile su S3/GitHub Pages per scenari aziendali

### v0.5 — Slack bridge
**Concetto pedagogico**: canali I/O asincroni, multi-actor identity.

- Slack bot via `github.com/slack-go/slack`, **Socket Mode** (niente public URL necessario).
- Form factor: **DM 1:1 + slash commands + mention nei canali**.
  - `/argus review <repo>` → trigger scan
  - DM = conversazione privata con l'agente
  - `@argus` in canale = chat condivisa con team
- Rendering finding: **Block Kit + link al report HTML** completo su `argus serve`.
- Allowlist su `user_id` Slack in `users.yaml`.
- Streaming risposte: `chat.postMessage` poi `chat.update` per evoluzione live del messaggio.
- Telegram bridge: opzionale, "contribution welcome", non sul critical path.
- Astrazione: `interface Channel { Send, Receive, Auth }` fin dall'inizio.

### v0.6 — Multi-repo / org + Multi-provider LLM
**Concetto pedagogico**: scaling, astrazione provider.

- Scope esteso: `argus review --org <github-org>` scansiona tutti i repo dell'organizzazione.
- Aggregazione report cross-repo nel renderer HTML.
- Parallelismo: pool di subagent per ridurre wall-clock.
- Implementazioni nuove dell'`interface Provider` definita in v0.1: `OpenAIProvider`, `AnthropicProvider` (eventualmente `OllamaProvider` per offline).
- Configurazione modelli in `argus.yaml` (alias `fast`, `smart`, `local`, come WildGecu).

### v0.7 — MCP server + Webhook + Authz a ruoli
**Concetto pedagogico**: interoperabilità agentic, RBAC.

- MCP server (Model Context Protocol) — espone:
  - **Resources**: `list_reports`, `get_report(repo, sha)`
  - **Tools**: `trigger_review(repo_url)`, `diff_reports(repo, sha1, sha2)`, `get_findings(repo, severity?)`
  - Auth: bearer token
  - Permette a Claude Code / altri client MCP di usare Argus come backend di sicurezza.
- Webhook HTTP per integrazioni GitHub Events (push, PR, release). Signature verification HMAC.
- Ruoli utente: `admin`, `analyst`, `viewer`. Policy file (YAML). Esempio: `viewer` può solo leggere report; `analyst` può triggerare review; `admin` può modificare cron, scope pentest, ruoli.

### v1.0 — Black-box pentesting (con safeguards non-negoziabili)
**Concetto pedagogico**: safeguards critici, sandbox/isolation, separation of privilege.

Tutti i seguenti **6 safeguard sono default non bypassabili**:

1. **Target allowlist** in `~/.argus/pentest-scope.yaml`:
   ```yaml
   scopes:
     - name: "RedCarbon staging"
       targets: ["staging.redcarbon.ai", "10.0.0.0/24"]
       expires: 2026-06-30
       authorized_by: davide.imola@redcarbon.ai
       active_authorized: false   # passive default
       rules_of_engagement: |
         No active exploitation. Recon + non-disruptive checks only.
   ```
   Nessuno scope, nessuna scan. Scope scaduto → blocco.

2. **Due modalità**: `passive` (default) vs `active` (richiede `--i-have-authorization` + `active_authorized: true` nello scope).
   - Passive: DNS, whois, certificate transparency, robots.txt, banner HTTP, info pubblica.
   - Active: nuclei, gobuster, nmap version scan, solo con autorizzazione esplicita.

3. **Hard-coded denylist** (if-statement Go, NON prompt instructions): mai exploit/RCE payload, mai DoS testing, mai brute-force credenziali, mai SQL-injection con write/delete. Gli LLM possono essere convinti, le `if` no.

4. **Audit verbose dedicato** in `~/.argus/pentest-audit.log.jsonl` con hash-chain, separato dall'audit log normale.

5. **Per-target rate limit**: max N req/sec configurabile, sleep automatico tra batch.

6. **Pentester subagent SEMPRE in sandbox Docker**: network namespace separato, no accesso disco locale, no accesso a secret del parent (parent passa solo target + scope, niente API key).

### Post-v1.0 — Goal-driven autonomy (opzionale, watcher)
**Concetto pedagogico**: true autonomous behavior con safeguards.

- Modulo opzionale `watcher`: l'agente ha goal persistenti, ogni X minuti si "sveglia" e decide cosa fare (nuovo repo creato? nuovo CVE? PR aperta security-sensitive?).
- **Budget dedicato e kill-switch**: un loop runaway non deve poter superare un cap separato.
- Sempre disattivato di default.

---

## 4. Cross-cutting (presenti dalla v0.1)

### Audit log
- Formato: **JSONL append-only con hash-chain** in `~/.argus/audit.log.jsonl`.
- Ogni riga ha `prev_hash` (sha256 della riga precedente) → tamper-evidence per compliance.
- Eventi loggati: `session_start`, `session_end`, `llm_call` (prompt hash + tokens + cost + model), `tool_call` (nome + args sanitizzati + exit code + durata), `subagent_spawn`, `finding_created`, `finding_dismissed`, `soul_updated`, `memory_updated`, `budget_exceeded`.

### Cost guardrails
Tre livelli, tutti attivi da v0.1:

1. **Per-call accounting**: pricing in `~/.argus/pricing.yaml`, calcolato a ogni LLM call, registrato in audit.
2. **Budget cap giornaliero/mensile** in `~/.argus/budget.yaml`. Superato → nuovi LLM call respinti (CLI/Slack mostrano warning). Override: `--force-budget`.
3. **Per-session cap**: hard limit token cumulativi (default 200k). Superato → session terminata, audit `session_budget_exceeded`.
Comando: `argus costs --since 7d`.

### Authorization
- v0.1–v0.4: single-user via `$USER` OS, nessun check.
- v0.5: allowlist Slack user_id in `users.yaml`.
- v0.7+: ruoli admin/analyst/viewer con policy file.

### Stop conditions agent loop
- Naturale: tool `finalize_report`.
- Safety nets paralleli: max 50 turn, ~200k token cumulativi, 10 min wall-clock.

---

## 5. Layout filesystem (home utente)

```
~/.argus/
├── .env                          # GEMINI_API_KEY, GITHUB_PAT, SLACK_* (v0.5)
├── argus.yaml               # providers, models, budget, scheduling
├── SOUL.md                       # v0.2 — identità + frontmatter
├── MEMORY.md                     # v0.2 — curato da memory-agent
├── context/                      # v0.2 — knowledge aziendale on-demand
│   ├── architecture.md
│   ├── threat-model.md
│   ├── compliance-soc2.md
│   ├── known-fps.md
│   └── escalation.md
├── skills/                       # v0.3 — markdown lazy-loaded
│   ├── whitebox-review/SKILL.md
│   ├── secret-scan/SKILL.md
│   └── dep-audit/SKILL.md
├── subagents/                    # v0.3 — SOUL per tipo
│   ├── secret-scanner/SOUL.md
│   ├── dep-auditor/SOUL.md
│   └── threat-modeler/SOUL.md
├── reports/                      # v0.1 — markdown + YAML frontmatter
│   └── <repo-slug>/
│       └── <sha>.md
├── cache/                        # v0.1 — git clone cache per SHA
│   └── <repo-slug>/<sha>/
├── pricing.yaml                  # v0.1 — pricing per modello
├── budget.yaml                   # v0.1 — cap giornaliero/mensile
├── users.yaml                    # v0.5 — allowlist + ruoli
├── pentest-scope.yaml            # v1.0 — target authorization
├── audit.log.jsonl               # v0.1 — hash-chained
└── pentest-audit.log.jsonl       # v1.0 — separato
```

---

## 6. Layout codice (Go)

```
argus/
├── go.mod
├── argus.go                 # main
├── cmd/                          # cobra commands
│   ├── root.go
│   ├── review.go                 # v0.1
│   ├── init.go                   # v0.2 — bootstrap interview
│   ├── start.go                  # v0.4 — daemon lifecycle
│   ├── stop.go, status.go, logs.go
│   ├── cron.go                   # v0.4 — cron ls/add/rm
│   ├── skill.go                  # v0.3 — skill ls/add
│   ├── slack.go                  # v0.5 — pairing/install
│   ├── costs.go                  # v0.1 — view spend
│   └── serve.go                  # v0.4 — HTTP renderer
├── pkg/
│   ├── agent/                    # agent loop, prompt assembly, stop conditions
│   ├── provider/                 # interface Provider
│   │   ├── provider.go
│   │   └── gemini/               # GeminiProvider (v0.1)
│   │       └── gemini.go
│   ├── session/                  # message history, context budget
│   ├── skill/                    # SkillLoader (markdown frontmatter)
│   ├── subagent/                 # spawn_agent, isolated context
│   ├── soul/                     # SOUL parser+writer + bootstrap interview
│   ├── memory/                   # memory-curator subagent
│   ├── context/                  # list/read tools per knowledge aziendale
│   ├── audit/                    # JSONL hash-chain logger
│   ├── budget/                   # cost calculator, daily cap, per-session cap
│   ├── github/                   # PAT auth, clone+cache per SHA
│   ├── security/                 # wrappers su semgrep, gitleaks, trivy, govulncheck
│   ├── report/                   # markdown writer + finding-id (hash snippet)
│   ├── render/                   # html/template, Chart.js, argus serve
│   ├── daemon/                   # Unix socket, gocron
│   ├── channel/                  # interface Channel
│   │   └── slack/                # Socket Mode bridge (v0.5)
│   ├── mcp/                      # MCP server Resources+Tools (v0.7)
│   └── pentest/                  # v1.0 — scope, denylist, sandbox Docker
└── ARCHITECTURE.md               # questo documento
```

---

## 7. Decisioni chiave (riferimenti rapidi)

| Decisione | Scelta | Quando |
|-----------|--------|--------|
| Linguaggio | Go | da v0.1 |
| Tool calling | Native Function Calling Gemini | da v0.1 |
| Storage | Markdown + frontmatter YAML | da v0.1 |
| Two-layer reporting | Agent→markdown, renderer Go→HTML | renderer in v0.4 |
| Finding ID | `hash(rule_id + normalized_snippet)` | da v0.1 |
| Subagent | Ephemeral spawn (pattern WildGecu) | da v0.3 |
| SOUL per subagent | Sì, file dedicato per tipo | da v0.3 |
| Soul/Context | SOUL+frontmatter via interview; CONTEXT folder on-demand | da v0.2 |
| Memory curation | Subagent dedicato a fine sessione | da v0.2 |
| Audit log | JSONL append-only + hash-chain | da v0.1 |
| Authz | Single-user → allowlist Slack (v0.5) → ruoli (v0.7) | progressivo |
| Daemon | Unix socket + gocron in-process | da v0.4 |
| Canale primario | Slack (Socket Mode) | da v0.5 |
| Slack UX | DM + slash + mention | v0.5 |
| MCP | Resources + Tools, bearer token | v0.7 |
| Multi-provider | Interface da v0.1; Gemini only fino a v0.6 | v0.6 |
| Sandbox | Nessuno fino a v0.7; Docker obbligatorio per pentest in v1.0 | v1.0 |
| Autonomia | Scheduled-proactive (cron-driven); goal-driven post-v1.0 con budget dedicato | v0.4 base |
| Cost guardrails | Per-call + daily cap + per-session cap | da v0.1 |
| Stop condition | `finalize_report` + 50 turn / 200k tok / 10 min | da v0.1 |

---

## 8. Concept pedagogici per anello

| Anello | Cosa impari |
|--------|-------------|
| v0.1 | Agent loop sincrono, native tool calling, prompt assembly, stop conditions, token budget. |
| v0.2 | Prompt assembly dinamica, context economy, identità persistente, memory curation come subagent. |
| v0.3 | Delega via spawn, isolamento context, riusabilità via skill markdown, model override per cost. |
| v0.4 | Daemon lifecycle, IPC Unix socket, scheduling persistente, separazione data/view. |
| v0.5 | Canali asincroni, multi-actor identity, Block Kit, streaming live message updates. |
| v0.6 | Scaling parallelismo, astrazione provider, alias di modelli. |
| v0.7 | Interoperabilità MCP, RBAC, webhook + signature verification. |
| v1.0 | Safeguards layered, sandboxing Docker, denylist hard-coded vs prompt-based safety. |

---

## 9. Riferimenti

- **WildGecu**: https://github.com/ludusrusso/wildgecu — specchio architetturale primario.
- **OpenClaw**: https://github.com/openclaw/openclaw — riferimento per multi-channel e sandboxing.
- **Gemini Go SDK**: `google.golang.org/genai` — provider primario.
- **Slack Go SDK**: `github.com/slack-go/slack` — bridge v0.5 (Socket Mode).
- **gocron**: scheduler in-process v0.4.
