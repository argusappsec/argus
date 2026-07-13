# Skill di autorizzazione white-box — panorama, lacune e design

> Stato: **implementata** — il design è atterrato come skill built-in
> `authz-audit` (`pkg/skill/builtin/authz-audit/`), validata con 100% di recall /
> 100% di precision su VAmPI (vedi [docs/guide/skills.md](../guide/skills.md)).
> Questo documento conserva il razionale: cosa costruire per la rilevazione
> white-box dei bug di logica di autorizzazione (BOLA / IDOR / BFLA), perché le
> opzioni pronte all'uso non li coprono, e come lo fa una skill nativa di Argus.
>
> Materiale collegato: `CONTEXT.md` (definizioni di Tool/Skill), ADR 0005 (forma
> delle skill — modello a directory-bundle), ADR 0006 (niente tool di shell
> generico), e la pagina utente della skill in [docs/guide/skills.md](../guide/skills.md).
>
> Nota: versione italiana di `authz-skill-design.md`. In caso di divergenza, la
> versione inglese fa fede (vive accanto agli altri doc del repo).

---

## 1. Il problema in una riga

BOLA (Broken Object Level Authorization, OWASP **API1:2023**) è un bug
**semantico**, non **sintattico**. Il difetto è *l'assenza di un controllo di
ownership che dovrebbe esserci*, misurata rispetto al modello di autorizzazione
dell'applicazione — di solito non documentato. Non c'è un sink pericoloso da
intercettare né una stringa ad alta entropia da segnalare. Questo singolo fatto
decide tutto ciò che segue: gli strumenti basati su pattern non possono trovarlo
per costruzione, e un LLM che *legge e ragiona sul codice* è lo strumento
giusto.

Evidenze raccolte (fonti in §9):

- Dalla documentazione di Semgrep: un pass LLM ingenuo su app reali produce
  **78–88% di falsi positivi** su IDOR/BOLA.
- La regola CodeQL `cs/web/insecure-direct-object-reference` è classificata solo
  **media precisione**, con valanghe di falsi positivi documentate quando
  l'autorizzazione vive in middleware / attributi / call-chain
  (github/codeql#16327).
- Sia Semgrep sia CodeQL dicono che l'unica via statica affidabile sono **regole
  scritte a mano e specifiche dell'applicazione** — che "poche squadre hanno il
  tempo, le risorse o le competenze" per scrivere.

---

## 2. La linea di demarcazione: pattern → tool, semantico → skill

È la spina dorsale dell'intera strategia. Dice quali problemi giustificano una
skill e quali invece *non* dobbiamo reimplementare come skill.

| Classe di vulnerabilità | OWASP | Rilevazione | Proprietario |
|---|---|---|---|
| **BOLA / IDOR** | API1 / A01 | semantica | **Skill** |
| **BFLA** (funzione admin, senza role-gate) | API5 | semantica | **Skill** |
| **Logica di access-control** (fail-open, trust-client) | A01 | semantica | **Skill** |
| **BOPLA** (mass-assignment / esposizione eccessiva) | API3 | ibrida | **Skill** |
| Auth rotta (alg=none, reset token indovinabile) | API2 | ibrida | Tool + Skill |
| SSRF | API7/A10 | ibrida | Tool (sink) + Skill (bypass) |
| Deserializzazione insicura | A08 | ibrida | Tool (sink) + Skill (gadget) |
| Race / TOCTOU, rate-limiting, abuso di flussi di business | API4/API6 | semantica | Skill (come *ipotesi*) |
| **Injection (SQLi/cmd), path traversal, secret, misconfig** | A03/A05 | pattern | **Tool — non fare una skill** |

**Regola pratica:** se uno strumento deterministico (semgrep, gitleaks, e le
aggiunte dello Stream G trivy/trufflehog/govulncheck/osv-scanner) lo intercetta
in modo affidabile, l'unico compito della skill è *triage/conferma* dell'output
del tool — mai riscoprirlo a precisione peggiore e costo di token maggiore.

---

## 3. Opzioni pubbliche / pronte all'uso — cosa fanno e dove falliscono

Per "pubbliche" si intende: skill già caricabili in una sessione Claude Code,
più i comuni analizzatori statici di terze parti. I difetti ricorrenti sono
**costo**, **genericità** (nessun metodo authz) e **integrazione** (nessun
accesso al modello di autorizzazione dell'org né al report/MEMORY di Argus).

### 3.1 Skill di Claude Code disponibili in sessione

| Skill | Cosa fa | Difetti per il nostro caso d'uso |
|---|---|---|
| **`shannon`** | Pentester AI autonomo. Analizza il sorgente, sceglie i vettori d'attacco ed **esegue exploit reali** per *provare* le vulnerabilità (app web + API). | **Costo**: loop autonomo multi-step → forte consumo di token, richiede un tier Claude capace/costoso e gira sul *tuo* piano CC. **Serve un target in esecuzione**: prova i bug dinamicamente, quindi è DAST-sopra-il-sorgente, non un pass statico pre-merge a basso costo. Ampiezza **non deterministica**. → Ottimo come stadio di *conferma* di un'ipotesi specifica; strumento sbagliato per un triage BOLA statico, ampio ed economico su tutto il repo. |
| **`/security-review`** (built-in) | Security review del **diff** del branch in corso. | **Diff-scoped** (non enumera l'authz dell'intero repo). **Generalista**: nessuna metodologia BOLA, nessuna ricostruzione del modello di ownership. Gira sul tuo piano CC, i findings non finiscono nel report/MEMORY di Argus. |
| **`/review`, `/code-review`, `/simplify`** | Review di PR / bug di correttezza / pulizie. | Pensate per **correttezza e qualità**, non per la logica di autorizzazione. Nessun ragionamento authz. |
| **plugin `code-review-graph`** | Knowledge graph Tree-sitter: impatto/blast-radius, flussi, hub/bridge node. | Non è un cacciatore di vuln — è **struttura/impatto**. Ma è un buon *feeder*: l'enumerazione di route/flussi può fornire a una skill BOLA la sua route-table del PASS 1. Richiede uno step di build del grafo. |
| `diagnose`, `verify`, `tdd`, `deep-research`, … | Debug / verifica / ricerca. | Fuori ambito per la rilevazione authz. |

**Difetto strutturale condiviso da tutte:** girano dentro la *tua* sessione
Claude Code, sul *tuo* abbonamento CC, **senza accesso alle convenzioni di
autorizzazione dell'organizzazione** (SOUL/CONTEXT di Argus) e **senza via verso
report/MEMORY di Argus**. Sono general-purpose e cieche al contesto dell'org
target.

### 3.2 Analizzatori statici di terze parti

| Strumento | Difetto specifico per BOLA |
|---|---|
| **Regole Semgrep community / OSS** | Nessuna regola IDOR/BOLA generica affidabile. La doc di Semgrep dice che la rilevazione generica è impraticabile; servono regole custom specifiche dell'app. |
| **Suite CodeQL di default** | `insecure-direct-object-reference` / `missing-function-level-access-control` sono a media precisione, centrate su C#, e inondano di FP quando l'authz è in middleware/attributi (issue #16327). |
| **Semgrep Pro / Assistant (AI IDOR)** | La migliore del gruppo (~61% precisione, ~8× più veri positivi rispetto al solo-LLM) — **ma richiede una licenza Pro/Assistant a pagamento** e necessita comunque di triage umano. Dipendenza di costo + lock-in. |
| **gitleaks / trufflehog** | Completamente fuori ambito — secret via entropia/regex; nessun modello di route, handler o autorizzazione. |

**In sintesi:** ogni opzione pubblica è (a) basata su pattern e cieca alla
logica authz, (b) discretamente accurata ma **a pagamento** (Semgrep Pro),
oppure (c) capace ma **costosa e dinamica** (shannon). Nessuna è un pass
economico, statico, consapevole dell'org e specializzato su BOLA che si integri
con Argus.

---

## 4. Cosa possiamo costruire noi — e perché qui è meglio

Una **skill di autorizzazione white-box nativa di Argus**: puro contenuto
markdown (nessun nuovo tool Go necessario), che compone i tool che Argus ha già
(`read_file`, `grep`, `list_files`, `list_context`/`read_context`), ed emette i
finding tramite i control tool esistenti `add_finding` / `finalize_report`.

Perché una skill nativa di Argus batte l'appoggiarsi alle opzioni pubbliche:

1. **Costo.** Gira sul **provider e sul budget di Argus** (`pkg/provider`,
   incluso il backend Gemini; limitato da `pkg/budget`), non su un abbonamento
   Claude Code separato e costoso. Nessun piano CC per sviluppatore, nessuna
   licenza Semgrep Pro. Il tier del modello è una nostra scelta, governata dal
   tetto di budget dell'org.
2. **Specializzazione.** Codifica la metodologia authz a 6 pass (§6) che gli
   strumenti pronti all'uso esplicitamente *non* hanno. È la differenza tra il
   78% di FP e un segnale utilizzabile.
3. **Consapevolezza dell'org.** Può leggere le **convenzioni di autorizzazione**
   dell'organizzazione da `CONTEXT` (`auth-conventions.md`) e rispettare i
   falsi-positivi-accettati da **MEMORY** — contesto che nessuna skill pubblica
   possiede.
4. **Integrazione.** I findings finiscono nella stessa pipeline `report.Finding`
   dell'output di semgrep/gitleaks, con ID stabili derivati dal contenuto,
   bucket di severità e le superfici di audit/report del daemon.
5. **Sicurezza.** È **statica** — legge il codice, non esegue exploit. Nessun
   target in esecuzione, nessun blast radius, sicura da lanciare pre-merge su
   ogni PR. (Passa la palla a `shannon` solo quando un'ipotesi necessita di
   prova dinamica — §7.)
6. **Componibilità con i tool pubblici, non competizione.** *Ingerisce* l'output
   di semgrep per le classi ibride e *alimenta* shannon per la conferma. Riempie
   l'unica lacuna che i tool pubblici lasciano aperta.

È esattamente la tesi dei built-in ("Argus conosce out-of-the-box i workflow di
sicurezza comuni") applicata all'unico workflow che più necessita di una lettura
del codice simile a quella umana.

---

## 5. Architettura della skill

### 5.1 Dove vive

- **Built-in:** `pkg/skill/builtin/authz-audit/SKILL.md`, embeddata via `embed.FS`
  (`//go:embed all:builtin`) e risolta dal `skill.Catalog` accanto agli altri
  built-in. Invocabile via `/authz-audit` o scopribile dall'agent tramite
  `list_skills`/`read_skill`. Per l'ADR 0005 rivisto una skill è un
  **directory bundle** (`SKILL.md` + file di supporto opzionali letti via
  `read_skill_file`); `authz-audit` per ora è un singolo `SKILL.md`.
- **Override user-curated:** un bundle in `~/.argus/skills/authz-audit/` vince
  sulla built-in per nome (intero bundle), così un team può forkare e adattare
  iterando a costo basso senza perdere la versione upstream.

La skill è stata validata su un repo reale (VAmPI) *prima* di essere consolidata
come built-in — prima si itera su un target vero.

### 5.2 Forma (per ADR 0005)

```
---
name: authz-audit
description: Rilevazione white-box di autorizzazione rotta (BOLA/IDOR/BFLA)
  ricostruendo il modello di ownership dell'app e trovando i percorsi di accesso
  che saltano il controllo per-oggetto/per-ruolo che i loro pari applicano.
tags: [authorization, bola, idor, bfla, access-control, white-box]
---
# corpo: la metodologia a 6 pass (§6), il finding-contract (§6.2),
# e le regole di disciplina (non riportare finché la call-chain non è stata letta).
```

- Nessun campo `tools:` (ADR 0005 — l'RBAC è imposto al livello Tool).
- Il corpo è l'estensione del prompt; `/authz-audit` lo inietta come un singolo
  turno dell'agent.
- **Compone solo tool esistenti** (ADR 0006 — niente shell escape): enumerazione
  delle route via `grep`/`list_files`/`read_file`; nessun nuovo binario.

### 5.3 Contratto di output — mapping su `report.Finding`

`report.Finding` è una struct **piatta** (`Severity, RuleID, File, Line,
Snippet, Title, Description, Remediation`; l'ID è `sha256(rule_id + snippet
normalizzato)`). **Non** ha un campo confidence, **non** ha un campo di
classificazione, e ha una **sola** `Line`. Un finding BOLA è intrinsecamente più
ricco (due posizioni — la id-source e il sink di data-access — più una
confidence e una classificazione BOLA/BFLA). Decisioni di design:

- **Tassonomia di `RuleID`** (anche l'ancora dell'ID stabile):
  `authz/bola-missing-owner-predicate`, `authz/bola-mutation-unscoped`,
  `authz/bfla-missing-role-gate`, `authz/access-control-fail-open`.
- **`Line`** punta al **sink di data-access** (il punto di fix azionabile); la
  posizione della **id-source** + la route vanno in `Description`.
- **`Snippet`** = la riga vulnerabile di data-access (ancora dell'ID stabile;
  quando il fix aggiunge il predicato di owner, lo snippet cambia → il finding
  si auto-risolve).
- **Confidence + classificazione** sono codificate in `Description` (risolto:
  restano in `Description` — nessun campo di prima classe; vedi §8).
- Rubrica di **`Severity`** (enum chiuso): mutation/delete non scopata →
  `critical`; lettura di dato sensibile posseduto → `high`; controllo
  debole/parziale → `medium`; ipotesi absence-based a bassa precisione → `info`.

L'emissione usa i due **control tool** del loop dell'agent (`pkg/agent/agent.go`):
il corpo istruisce l'agent a chiamare `add_finding` una volta per ogni finding
confermato (`severity`/`rule_id`/`snippet` obbligatori; `file`/`line`/`title`/
`description`/`remediation` opzionali), poi `finalize_report(summary)` una sola
volta. Non serve alcun tool *nuovo* — la skill è **puro contenuto**.

---

## 6. Metodologia e superficie

### 6.1 Il metodo a 6 pass (ciò che il corpo codifica)

L'ordine dei pass esiste per **costruire il contesto di autorizzazione prima di
giudicare qualsiasi handler** — è questo che sconfigge la trappola del 78% di
FP.

0. **Ground model (mettilo in cache).** Rileva il framework + come dichiara le
   route (decorator? spec OpenAPI? annotazioni?). Trova l'**accessor del
   principal autenticato**. Mappa il **modello di ownership/tenancy** da
   schema/migrazioni (`owner_id`/`tenant_id`/FK). Inventaria il **vocabolario
   authz reale** del progetto (guard, policy, helper tipo `assertOwner`). Carica
   `auth-conventions` da CONTEXT se presente.
1. **Enumera** route → handler → metodo in una tabella.
2. **Filtra** agli handler che prendono un **identificatore di oggetto
   dall'input della request** (path/query/body/header/arg GraphQL).
3. **Traccia** ogni id fino al suo **sink di data-access**; etichetta read vs
   mutation.
4. **Verifica del guard, cross-file.** Tra l'ingresso della request e l'oggetto
   restituito/mutato, l'accesso è vincolato al principal/tenant corrente
   (predicato in query / confronto post-fetch / chiamata a policy / scope del
   base-repo / RLS del DB)? **Risolvi helper e middleware leggendoli, non per
   nome.**
5. **Classifica / disambigua.** BOLA (endpoint giusto, oggetto sbagliato) vs
   BFLA (endpoint del tutto sbagliato); orizzontale vs verticale; scarta le
   risorse intenzionalmente pubbliche.
6. **Ordina** per exploitability ed emetti il finding.

**Disciplina (nel corpo, intento testuale):** *non segnalare mai un handler
finché PASS 0 + PASS 4 non hanno effettivamente letto middleware/base-repo/policy
rilevanti.* Tratta "non trovo un guard in questo file" come "vai a leggere la
call chain", non come un finding. Dichiara la confidence e ciò che non sei
riuscito a risolvere.

### 6.2 Superficie coperta — in/out of scope esplicito

**In scope (questa skill se ne fa carico):**
- BOLA / IDOR — predicato di ownership per-oggetto mancante (API1 / A01).
- BFLA — funzione privilegiata priva del role-gate che i suoi pari hanno (API5).
- Logica di access-control generica — fail-open, ruolo fidato dal client,
  mismatch check-then-use, normalizzazione del path dopo l'authz (A01).

**Adiacente (segnalato come `info`, demandato a una skill sorella):**
- BOPLA / mass-assignment / esposizione eccessiva di dati (API3) → futura
  `object-property-audit`. La skill ci *inciamperà* sopra (es. un campo
  `admin` auto-assegnato) e dovrebbe annotarli, non farsene carico.

**Out of scope (compete agli strumenti deterministici):**
- Injection (SQLi/command/SSTI), path traversal, secret hardcoded, gran parte
  delle misconfig — `run_semgrep` / `run_gitleaks` / tool dello Stream G.
  Restare nella propria corsia qui è una *feature*: tiene basse precisione
  persa e costo.

**Bassa precisione, emessi come ipotesi (`info`):**
- Race/TOCTOU, rate-limiting mancante, abuso di flussi di business — solo
  advisory, candidati alla prova dinamica (§7).

---

## 7. Catena operativa — trova statico → prova dinamico

```
   semgrep / gitleaks ──(hit di pattern, input ibrido)──┐
   code-review-graph ──(tabella route/flussi per PASS 1)─┤
                                                         ▼
                                          ┌──────────────────────────┐
                                          │  authz-audit (SKILL)     │  statica, economica,
                                          │  6-pass, org-aware       │  org-aware, sicura
                                          └───────────┬──────────────┘
                          finding alta confidence     │ ipotesi bassa confidence
                                          ┌────────────┴────────────┐
                                          ▼                         ▼
                                   report.Finding            shannon (o manuale)
                                   + finalize_report         prova dinamica via exploit
                                                             (target in esecuzione, costoso)
```

`authz-audit` è la rete ampia, economica e statica; `shannon` è il confermatore
preciso, costoso e dinamico, usato **solo** sulla manciata di ipotesi che vale
la pena provare. È così che otteniamo copertura senza pagare il costo di shannon
su ogni endpoint.

---

## 8. Decisioni di design (risolte dalla validazione su VAmPI)

1. **Modello di report — RISOLTA: resta flat, niente campo `Confidence`.**
   Confidence, classificazione (BOLA/BFLA, orizzontale/verticale) e id-source
   stanno in `Description`; `Line` punta al sink. Lo standard (§5.3) per
   aggiungere un campo `Confidence` di prima classe era *"solo se la validazione
   mostra una riduzione di FP misurabile grazie ad esso."* La validazione
   genuinamente cieca su VAmPI ha prodotto **zero falsi positivi canonici** con
   la confidence in `Description` — la precision viene dal ground-model del PASS
   0 e dal verification gate, non da una colonna di metadati. Quindi: **niente
   campo `Confidence`, niente ADR.** Da rivedere solo se un target futuro produce
   FP che un campo confidence strutturato taglierebbe in modo dimostrabile.
2. **Confine di scope — RISOLTA: stretto.** BOLA/BFLA/access-control sono di
   competenza; la mass-assignment in *scrittura* è emessa come `info`
   (`authz/bopla-mass-assignment-adjacent`) con rimando a una futura
   `object-property-audit`; l'excessive-data-exposure in *lettura* resta
   out-of-lane (solo nota, nessun `authz/*` rule_id). La validazione conferma
   che è questo confine a tenere pulita la precision (l'unica sbavatura era una
   lettura `_debug` finita nello slot adiacente; la regola è stata stretta per
   vietarlo).
3. **Finding vs ipotesi — RISOLTA.** BOLA/BFLA ad alta confidence → finding
   pieni; le classi a bassa precisione/absence-based (race, rate-limit, business
   flow) → ipotesi `info`, candidate a un confermatore dinamico (es. `shannon`).
   Si lega all'avversione ai FP tracciata in MEMORY.

---

## 9. Piano di validazione (target: VAmPI)

VAmPI (`erev0s/vampi`, Flask + Connexion) è il primo target scelto perché il suo
toggle `vulnerable=1/0` fornisce un **dataset etichettato gratis**: ogni `if
vuln: … else: …` è una coppia allineata (vulnerabile, sicuro) nel sorgente.

**Ground truth (rilevante per authz), ricavata dal codice reale:**

| Endpoint / handler | Bug | Finding atteso |
|---|---|---|
| `GET /books/v1/{book_title}` → `books.get_by_title` | legge il `secret_content` di un altro utente (query `filter_by(book_title=…)`, senza owner) | BOLA read, **high** |
| `PUT /users/v1/{username}/password` → `users.update_password` | cambia la password di qualunque utente (`filter_by(username=…)` dalla URL, non da `resp['sub']`) | BOLA mutation, **critical** |
| `POST /users/v1/register` → `users.register_user` | si auto-assegna `admin` (manca `additionalProperties:false`) | mass-assignment → `info` (adiacente, API3) |

**Due metriche, entrambe dal toggle:**
- **Recall:** la skill trova i 2 endpoint BOLA-class?
- **Precisione / no-FP:** marca correttamente come **SAFE** i rami `else:`
  sicuri (che scopano su `resp['sub']`)? Segnalare l'`else` è il falso positivo
  canonico — il test di credibilità.

**Note che il framework impone (lezioni generalizzabili):**
- Il PASS 1 deve **parsare `openapi_specs/openapi3.yml`** (Connexion: lo spec
  *è* il router; non ci sono decorator di route).
- Principal = `resp['sub']` da `token_validator(request.headers.get(...))`.
- VAmPI **non ha alcun helper di autorizzazione** — solo authn — quindi il PASS
  0 dovrebbe registrare "nessun layer authz centralizzato" e alzare il prior di
  BOLA.
- La skill deve **restare fuori dalla corsia SQLi** (`users.get_user`, f-string
  in `text()`): è compito di `run_semgrep`, non di authz-audit.

**Roadmap dei target dopo VAmPI:** crAPI (microservizi realistici, BOLA+BFLA) →
Damn Vulnerable RESTaurant (FastAPI moderno, ruoli+ownership) → RailsGoat (spec
RSpec eseguibile dell'exploit IDOR come ground truth).

---

## 10. Riferimenti

- OWASP API Security Top 10 (2023): API1 BOLA, API3 BOPLA, API5 BFLA —
  <https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/>
- OWASP IDOR Prevention Cheat Sheet & WSTG Authorization Testing.
- PortSwigger Web Security Academy — Access control / IDOR.
- Semgrep: "Can LLMs detect IDORs" (2025) e blog AI-powered detection; doc IDOR
  di Semgrep (rilevazione generica impraticabile).
- CodeQL `cs/web/insecure-direct-object-reference`; github/codeql#16327 (report
  di FP per authz in call-chain/attributi).
- Target: `github.com/erev0s/VAmPI`, `github.com/OWASP/crAPI`,
  `github.com/theowni/Damn-Vulnerable-RESTaurant-API-Game`,
  `github.com/OWASP/railsgoat`.
