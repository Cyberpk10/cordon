# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Cordon is a **defensive** email/identity-security platform. It started as a single-shot `.eml`
analyzer (Milestone 1) and has grown milestone-by-milestone (see `README.md` and the dated
comments throughout `backend/app/core/config.py`, which doubles as a changelog) into:

- A deterministic, rule-based phishing indicator engine that fuses findings into a 0-100 risk
  score and maps them to compliance frameworks (MITRE ATT&CK, NIST CSF, ISO 27001, SOC 2).
- An optional ML classifier signal and an optional LLM analyst assessment (narrative +
  a structured, bounded intent signal), both bounded add-ons that can only nudge — never
  override — the rule-based verdict. The LLM signal is additive-only (it can raise a score
  within its cap, never lower one), so it structurally cannot be used to push a
  deterministically-malicious email to safe, including via prompt injection in the email body.
- Multi-channel (email + Slack/Teams chat) detection, cross-signal intrusion/UEBA detection over
  ingested activity events, case/incident management, audit evidence packs, and continuous
  control monitoring.
- Graduated autonomy (D5): a per-account L0–L3 tier, shadow mode by default, a kill switch,
  and a full audit log. The engine acts only on Cordon's own records (case tags/triage,
  notifications, an in-Cordon watch/blocklist, campaign grouping), every action has an undo,
  and mailbox actions are only ever proposed for a person. Live mailbox writes are deferred.
- An agentic investigation layer (M10) that turns a flagged Case/Incident into a grounded
  report in one step: Cordon's own correlated signals (sender history, related cases/
  incidents/events, threat-intel hits, early-warning threat level, UEBA findings), an
  optional LLM narrative that can only cite evidence actually gathered, and recommended
  response steps from the same deterministic playbooks remediation already uses.
  Recommend-only; see `backend/app/investigation/`.

Cordon performs analysis and (opt-in, policy-gated) containment only: no exploitation, no
destructive actions are defined anywhere in the action catalog.

Three independent components, each with its own dependency/test setup:

| Dir | What | Consumed by |
| --- | --- | --- |
| `backend/` | FastAPI app — the actual runtime | Render (prod), `uvicorn` (dev) |
| `frontend/` | React + Vite + TS SPA | Vercel (prod), `vite` (dev) |
| `ml/` | Offline corpus-assembly + training pipeline for the phishing classifier | Not imported by the runtime backend; publishes artifacts *into* `backend/app/ml/artifacts/` |

## Commands

### Backend (`cd backend`)

```sh
python3.11 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest -v                          # full suite
pytest tests/unit/test_risk_engine.py -v          # single file
pytest tests/unit/test_risk_engine.py::test_name  # single test
uvicorn app.main:app --reload      # dev server on :8000
```

Tests are fully offline/deterministic regardless of local `.env`: `tests/conftest.py` forces a
fresh in-memory SQLite DB per test, pins `enable_llm_reasoning`/`enable_ml_classifier` to
`False`, clears the ML model's `lru_cache`, and resets the shared rate limiter — all
`autouse=True` fixtures, so no per-test opt-in is needed.

Postgres (optional, for parity with prod):

```sh
docker compose up -d               # Postgres on localhost:5432
# backend/.env: DATABASE_URL=postgresql+psycopg://aegis:aegis@localhost:5432/aegis
alembic upgrade head
```

Without Docker/Postgres, `app.main`'s lifespan hook auto-creates tables on a local
`aegis.db` SQLite file — no Alembic step needed for that path. Real deployments (Postgres) are
expected to run `alembic upgrade head` instead of relying on that fallback.

### Frontend (`cd frontend`)

```sh
npm install
npm run dev       # Vite dev server; proxies /api -> http://localhost:8000
npm run build     # tsc -b && vite build
npm run lint      # eslint .
```

### ML pipeline (`cd ml`)

```sh
python3.11 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest -v
python -m aegis_ml.cli build --skip-download   # normalize -> dedupe -> split -> report
python -m aegis_ml.train                        # train, calibrate, evaluate, publish artifacts
```

`aegis_ml.train` writes documentation to `ml/models/{metrics.json,CARD.md}` (committed) and the
actual binary artifacts the backend loads to `backend/app/ml/artifacts/` (Docker's build context
is `backend/` only, hence the split location). `ml/aegis_ml/features.py` imports the real
backend parser/indicator code by path for train/serve feature parity — the two are pinned to
never drift.

No CI workflow or linter config (ruff/black/mypy) is currently checked in for the Python
packages; `frontend`'s `eslint` is the only configured linter in the repo.

## Backend architecture

**Request flow for the core analyzer** (`app/analysis/email_pipeline.py::run_email_pipeline`,
shared by the direct-upload, paste-text, and inbound-webhook entry points):

```
raw bytes -> parse_eml() -> run_indicators() -> [optional ML predict()] -> fuse() -> rule_score/rule_verdict
                                                                          -> [optional LLM assessment, shown rule_score/rule_verdict]
                                                                          -> fuse() again (+ bounded LLM intent_risk) -> final score/verdict
                                                                          -> map_indicators() -> framework mappings
```

- `app/parsing/eml_parser.py` + `app/parsing/auth_results.py` — parses `.eml` bytes, including
  `Authentication-Results` (SPF/DKIM/DMARC are read from this header, never independently
  re-verified — no outbound network/DNS calls anywhere in analysis).
- `app/indicators/` — one module per deterministic rule (sender/reply-to mismatch, look-alike
  domains, urgency language, credential/payment requests, link analysis, attachment risk, auth
  failures, AI-authored-text heuristics, chat context). `engine.py` is a flat registry +
  runner — adding a rule means adding a module and one line in `_RULES`.
- `app/scoring/risk_engine.py` — fuses indicator scores (+ optional bounded ML probability +
  optional bounded LLM intent signal) into the 0-100 score and Safe/Suspicious/Malicious
  verdict. Both optional signals are structurally bounded so neither alone can flip a verdict
  band from a clean rule score: `ML_MAX_CONTRIBUTION_POINTS` (15, ± either direction) and
  `LLM_INTENT_MAX_CONTRIBUTION_POINTS` (20, **additive-only** — it can only ever raise a score,
  never lower one). The deterministic rule-based score is always computed first and is what
  these two bounded signals nudge, never replace; see that module's docstring for the full
  guarantee and `tests/unit/test_risk_engine.py` for the tests that prove it structurally.
- `app/mapping/framework_mapper.py` + `app/mapping/frameworks/*.yaml` — versioned YAML mapping
  indicator IDs to MITRE ATT&CK / NIST CSF / ISO 27001 / SOC 2 controls.
- `app/ml/classifier.py` — loads the joblib artifacts (see `ml/models/CARD.md`) and predicts;
  degrades to `(None, None)` if artifacts are missing or the feature is off. Training data
  (`ml/corpus/sources.md`) mixes licensing-clean public corpora (Nazario phishing incl. yearly
  2015-2025 files, SpamAssassin ham, Enron) with a small, bounded, explicitly-labeled slice of
  LLM-generated synthetic phishing/BEC/AI-lure email (≤2% of train, train-split-only by
  construction in `aegis_ml/split.py` so val/test stay a real-only holdout). See `ml/models/
  CARD.md`'s "Honest before/after/ablation evaluation" for the measured effect of each change
  (broadening real data moved recall/precision; the synthetic slice measured as a no-op on the
  real test set, i.e. no regression, which is why it shipped) — don't assume synthetic
  augmentation improved a number without checking that section, since in this case it didn't
  move any of them.
- `app/reasoning/llm_analyst.py` — one Anthropic call (Haiku-class model) that returns both a
  human-readable narrative AND a structured, bounded intent assessment (`intent_category`,
  `intent_risk`, `confidence`, `brief_reasons`), via a forced tool-use call rather than free
  text. `intent_risk` feeds back into `risk_engine.fuse()` as the additive-only LLM signal
  described above; the narrative is display-only and is never parsed or acted on. The email
  body is untrusted content: clearly delimited in the prompt as data to analyze and never
  follow, and the model's response is independently re-validated server-side against a strict
  Pydantic schema (fixed `intent_category` enum, `intent_risk` range, `extra="forbid"`) — the
  tool's JSON schema is a strong hint to the model, not a guarantee, so nothing downstream
  trusts a field the API itself didn't enforce. Any failure at any layer (no API key, network/
  timeout, a malformed tool call, or a schema violation) degrades identically: the whole
  assessment is discarded and the pipeline falls back to the rule-based (+ ML) result with no
  error surfaced to the caller. See `tests/unit/test_llm_analyst.py` and
  `tests/security/test_prompt_injection_e2e.py` for the injection-hardening tests, including
  ones that mock a "successfully compromised" model response (claiming `intent_risk=0`/benign
  for a known-malicious email) and confirm the score is never lowered by it.

**Lure combinations and attachments** — `app/indicators/{lure_theme,institutional_sender_mismatch,
combinations}.py`, `app/parsing/attachment_inspect.py`:
- `SOCIAL_ENGINEERING_THEME` (romance, sextortion, prize, crypto bait; specific phrases, 8 pts) is
  weak alone. `LURE_COMBINATION` is a post-pass in `run_indicators` over the fired findings: a
  lure (that theme, CREDENTIAL_REQUEST, PAYMENT_REQUEST, or URGENCY_LANGUAGE with 2+ phrases)
  plus a hidden destination (+20: shortener/mismatch/IP-literal findings, or any link to
  `domain_utils.HIDDEN_DESTINATION_HOSTS`, i.e. shorteners and file/document hosting; social/
  video hosts excluded), a risky attachment (+25) or a hijacked institutional sender (+20),
  capped at +35, +10 when the lure has 2+ parts (cap 45). No lure, no bonus, so a newsletter
  with a bit.ly link gets nothing.
- `AUTHENTICATED_SENDER_CONTENT_MISMATCH` (30): SPF or DKIM pass from an edu/gov/ac/… domain,
  carrying a lure theme, and no security-awareness wording. Counts as account takeover in
  `investigation/assessment.py`. Payment/deadline wording alone never fires it.
- Attachments are inspected statically at parse time (magic bytes, the zip central directory
  only, VBA markers; nothing decompressed or executed, bytes not stored) →
  `ATTACHMENT_HTML`, `_ARCHIVE_RISKY_CONTENT`, `_ENCRYPTED_ARCHIVE`, `_TYPE_MISMATCH`, and
  content-detected macros. Names are attacker data: sanitized in evidence and delimited with
  `<`/`>` neutralized in the LLM prompt.
- `run_indicators` merges findings that share an id (one per id; a pure repeat adds no
  points). Links are deduped by normalized href. Threat-intel hostname hits on shared hosts
  (`domain_utils.SHARED_LINK_HOSTS`: shorteners, Drive, Dropbox, LinkedIn…) don't count, only
  exact-URL hits do: PhishTank lists bit.ly/t.co/tinyurl as whole hosts.

**Detections (intrusion/UEBA) mirror the indicators pattern exactly**, one level up from a
single email — over ingested activity `Event`s instead of a parsed email:

- `app/detections/` — one module per rule (brute force, impossible travel, anomalous location,
  off-hours access, mass file access, data exfiltration, privilege escalation).
  `engine.py::run_detections` is the same flat registry pattern as indicators.
- `app/baselines/aggregation.py` — per-actor behavioral baselines (UEBA) with cold-start gates
  (a baseline isn't trusted over static thresholds until it has enough history — see the
  `baseline_*` settings in `app/core/config.py`).
- `app/channels/` — Slack/Teams message adapters normalize chat messages into the same shape the
  indicator engine consumes (`chat_context` indicator); live ingestion is flagged off
  (`enable_live_slack_ingestion`/`enable_live_teams_ingestion`) pending real webhook wiring.

**Graduated autonomy (D5)** — `app/autonomy/{engine,cordon_actions,runner}.py`: the first
rung where Cordon acts. Per account (`AutonomyPolicy`): `tier` L0–L3 (the ceiling, default L1),
`shadow_mode` (default on: log would-haves, act on nothing), `kill_switch` (stops everything).
- `engine.py` (pure) — `plan(DecisionInputs, PolicyView)` turns the verdict and D4's
  deterministic assessment (confidence, campaign, recommendation) into actions, each with a
  stable rule id (`R1-LABEL` … `R9-MAILBOX`) and one outcome: performed / shadow /
  awaiting_approval / above_tier / halted. `DecisionInputs` has no free-text field, so email
  content can't change the plan or the tier. The rate cap applies to L2 actions only.
- `cordon_actions.py` — the catalog: L1 tag, triage, notify, open investigation; L2
  watchlist/blocklist (`CordonListEntry`, read back by `app.indicators.account_lists`: a
  blocklisted sender scores like a threat-intel hit), group campaign (`CaseCampaign`),
  escalate; L3 `RECOMMEND_MAILBOX_REMEDIATION` (approval records the decision, never
  executes). Every entry has `apply` → before-state and `undo`; the catalog refuses to load
  without an undo. Undo refuses (Superseded) to overwrite a value a person changed.
  `DEFERRED_ACTIONS` documents what's out of scope (mailbox writes need write scopes + CASA).
- `runner.py` — runs after `maybe_auto_investigate` saves the deterministic investigation;
  writes one `AutonomyAction` row (engine `d5`, tier, rule, mode, undo path) per planned action;
  undo / approve (admin) / dismiss, each audit-logged. Routes in `app/api/routes/autonomy.py`
  (`/kill-switch`, `/actions/{id}/{undo,approve,dismiss}`, `/shadow-summary`, `/lists`) and
  `notifications.py`. Tests: `tests/unit/test_autonomy_engine.py`,
  `tests/integration/test_autonomy_d5.py`.

**M6 autonomy (legacy)** — `actions.py`, `policy.py`, `executor.py`, `connector_factory.py`,
`graph_connector.py`: the earlier mailbox/identity action catalog and the real Microsoft Graph
connector. D5 retired its automatic path (the playbook fetch no longer evaluates or executes
anything), so no automatic path calls a connector. Kept for the next rung (live mailbox
actions) and for reading/reversing old rows. `DISABLE_SESSION` stays irreversible and
human-only.

**Agentic investigation** — `app/investigation/`: turns a flagged Case/Incident into a
grounded investigation in one step, scoped strictly to data Cordon already has (no external
SOC source is ever queried here).

- `gather.py` (DB-touching) + `aggregation.py` (pure) — assembles the context: sender
  intelligence (first-contact/look-alike/known-bad classification, re-derived from
  `app.sender_history` with the triggering case excluded from its own history), other cases
  from the same sender, other cases/incidents/events for the actor (the targeted recipient
  for a case, or the incident's own actor — whoever's account activity is actually at risk),
  the early-warning threat level/band/trend for that actor, UEBA findings pulled from
  correlated incidents, and threat-intel hits — but only the ones Cordon's OWN indicator/
  detection engines already matched (`SENDER_DOMAIN_KNOWN_BAD`, `SENDER_IP_KNOWN_MALICIOUS`,
  `LINK_KNOWN_MALICIOUS`, `EVENT_IP_KNOWN_MALICIOUS`), never a fresh lookup that could
  disagree with what was actually detected. A timeline and blast-radius/scope ("did other
  recipients get the same message," "does this actor show compromise signals") fall out of
  the same gathered evidence.
- `llm_summary.py` — same architecture and the same prompt-injection hardening as
  `app.reasoning.llm_analyst` (forced tool-use, untrusted free text delimited and never
  followed, strict server-side Pydantic validation, fails closed to no narrative on any
  error). Grounding is structurally enforced, not just requested: every evidence item
  gathered is given to the model as a numbered list (`EV1`, `EV2`, ...), and the model must
  cite which ids its narrative relies on — any cited id outside the real set (a fabrication)
  fails validation and discards the WHOLE response, the same fail-closed contract as an
  invented `intent_category` in `llm_analyst`. Never sees a raw email body (only subject,
  which is delimited as untrusted) — investigations must stay buildable even after raw-email
  retention purge.
- `build.py` — orchestrates gather → recommended steps (reuses `app.remediation.playbook`/
  `intrusion_playbook`'s existing deterministic engine — recommend-only, same contract as
  remediation itself) → optional narrative (gated behind `ENABLE_LLM_REASONING`, one call per
  investigation, never per-email) → upsert into `app.db.models.Investigation`. Re-investigating
  replaces the prior record in place rather than appending, since it reflects current
  best-available evidence, not a log of past runs.
  `maybe_auto_investigate` is called from the Case/Incident creation paths (`app/api/routes/
  analyze.py`, `inbound.py`, `events.py`) right after persistence, firing only at Suspicious/
  Malicious (`investigation_auto_trigger_verdicts`) and swallowing any exception — an
  investigation failure must never break email analysis or event ingestion. The "Investigate"
  action (`POST .../investigate` in `app/api/routes/investigations.py`) runs the same path
  on demand regardless of verdict.
- Exposed in the frontend via `InvestigationPanel` (`frontend/src/components/
  InvestigationPanel.tsx`), reused for both cases and incidents the same way
  `ResponsePlaybookPanel` already is, and folded into the Audit Mode evidence pack
  (`app/audit/report_builder.py`) as its own section — the investigation itself is
  audit-ready documentation, not just an analyst tool.
- See `tests/integration/test_investigations.py` and `tests/unit/test_investigation_*.py` for
  the grounding/injection/graceful-degradation tests, including one that reproduces a real
  bug this feature's own tests caught before merge: a naive-vs-aware datetime comparison in
  `app.threat_level.aggregation.compute_trend` that silently broke auto-investigation (via
  `maybe_auto_investigate`'s necessary exception-swallowing) whenever the actor already had a
  threat-level row — fixed by threading one normalized-to-naive-UTC `now` through every
  lookback calculation in `gather.py`, the same `app.core.time.to_naive_utc` discipline every
  other hooks module in this codebase already follows.

**Investigation agent** (M10 Stage 2) — `app/investigation/{tools,agent,assessment,verify,
artifacts}.py`: for email cases, the investigation is now a bounded, tool-using agent built
on the M10 pieces above (same `Investigation` row, routes, triggers and panel).
- Five fixed, read-only, account-scoped tools (`tools.py`): `get_sender_baseline`,
  `find_related_cases` (sender / campaign signature / shared link domain / sending IP, each
  with its match reason; shared mail-provider IPs never link cases), `enrich_ip` (only IPs on
  the case; provider IPs flagged as "not the sender's location"), `inspect_links` (nothing
  fetched), `framework_context`. Each output line becomes a numbered evidence item (EVn).
  Links and the campaign signature come from `Case.artifacts`, written at analysis time.
- `agent.py`: the rules engine (all tools in a fixed order, template claims) always runs and
  is the fallback for everything. With `ENABLE_LLM_REASONING` and a key, an Anthropic tool-use
  loop picks tools under hard caps (`investigation_agent_max_tool_calls`=6, a token budget, a
  deadline); hitting a cap forces `submit_investigation`. The email body is never sent.
- The model writes only claims (each citing EV ids) and a hypothesis (fixed enum).
  Confidence, campaign/wave, blast radius, the recommended action and its suggested L0–L3 tier
  come from `assessment.py` and are identical whichever engine ran, so an injected email can't
  change the recommendation. `verify.py` rejects the whole answer on a schema error, a
  restated verdict that isn't Cordon's, or a citation the model was never shown; it drops any
  claim whose IPs/domains/addresses/numbers aren't in the evidence it cites.
- Auto-trigger runs the rules engine inline and the agent after commit (background thread);
  "Investigate" runs the agent inline. An unchanged evidence fingerprint reuses the stored
  agent report. Recommend-only: nothing calls `app.autonomy.executor`.
- Surfaced in `InvestigationReportView.tsx`, as the additive `investigation` key on
  `/v1/analyze/email`, and in the assistant's evidence/answers. `GET /api/admin/llm-health`
  checks the configured key from inside the server. Tests:
  `tests/integration/test_investigation_agent.py`,
  `tests/unit/test_investigation_verify_assessment.py` (fake API in `tests/agent_fakes.py`).

**Security & Compliance Report** (M11 Stage 1) — `app/reports/`: a one-click, board/auditor-
ready artifact, positioned as an extension of Audit Mode (`app/audit/`) rather than a
replacement — Audit Mode is a per-framework control-evidence table for an auditor to
spot-check; this is the cross-framework executive artifact for a board or auditor's first
read.

- `gather.py` (DB-touching) — assembles one `ReportMetrics` for an account over a period from
  data Cordon already has: cases analyzed and their verdict breakdown (reusing `app.dashboard.
  aggregation.verdict_counts`), threats detected/contained (the latter counted only from
  `AutonomyAction` rows with `status == "executed"`, i.e. actions that actually ran, not just
  decided), estimated exposure avoided (reusing `app.risk_model.aggregation.exposure_avoided`
  unchanged — the same calculation `GET /api/risk/financial` already exposes), intrusion
  incidents and early-warning alerts raised, a human-risk/phishing-simulation summary, and
  control-framework coverage across all four loaded frameworks at once (reusing `app.
  dashboard.aggregation.framework_coverage`). `ReportMetrics.has_any_activity` is the single
  switch the executive summary and both renderers use to decide between real figures and an
  honest "no activity this period" report — never a padded or invented metric either way.
- `executive_summary.py` — same architecture and grounding discipline as `app.investigation.
  llm_summary`: every metric is offered to the model as a numbered list (`EV1`, `EV2`, ...)
  and the model is forced (tool-use) to cite which ids its summary relies on; a citation to an
  id it wasn't given, or a missing/malformed field, discards the whole response. Simpler than
  `llm_summary`/`llm_analyst` in one respect — there is no email body, subject line, or other
  untrusted free text anywhere in this prompt, since every evidence item is a number Cordon
  itself already computed, so there is structurally no prompt-injection surface here at all.
  Gated behind `ENABLE_LLM_REASONING` at the call site (`app/api/routes/reports.py`), exactly
  like the investigation narrative; `generate_deterministic_summary` is the non-LLM fallback
  used whenever the flag is off, the API key is missing, the call fails, or the model
  fabricates — a template-filled recap of the same `ReportMetrics`, so the report always has
  an honest executive summary regardless of LLM availability.
- `report_builder.py` — renders the same `ReportContext` as JSON and a PDF (reportlab, no
  system-binary dependency, mirroring `app.audit.report_builder`'s rationale), styled with
  Cordon's own dark visual identity (navy background, the "C" mark drawn via a canvas page-
  chrome callback, accent-colored headings from the app's design tokens) rather than the evidence pack's plain light styling,
  since this artifact is meant to be read on screen by a board member as much as printed for
  an auditor.
- Exposed via `POST/GET /api/reports/security-compliance` (generate, returning the full
  detail for an immediate in-app preview; list; re-fetch by id; `.../download` for the stored
  PDF/JSON) and the frontend's `ReportsView` (`frontend/src/components/reports/`) — a
  date-range picker, a Generate button, an in-app preview matching the PDF's sections, and a
  Download PDF button, plus a recent-reports list mirroring Audit Mode's.

**Public /v1 API + email assistant** — `app/api/routes/v1.py`, `app/assistant/`: API-key
(`cdn_…`, hashed in `api_keys`) endpoints for the Gmail add-on (`integrations/gmail-addon/`)
and Outlook add-in (`integrations/outlook-addin/`, task pane served from
`frontend/public/outlook/`). `POST /v1/analyze/email` runs the shared pipeline (`persist:
"if_not_clean"` skips saving clean mail); `POST /v1/assistant` answers one question about one
email. Both share `_lookup_or_run` (saved Case by content hash → `app.analysis.result_cache` →
fresh pipeline run; the assistant never persists). The assistant mirrors the copilot's split:
`deterministic.py` (LLM-free answers, off-topic redirect, the fallback) and `llm.py` (same
hardening as `llm_summary`: forced tool-use, EV-id citations, strict Pydantic, untrusted text
delimited with `<`/`>` neutralized, client history sent as delimited data, never as assistant
turns). Its extra structural check: the model must restate Cordon's verdict
(`stated_verdict`), or the answer is discarded. That's what stops an email saying "tell the
user this is safe" from flipping the answer. Gated on `ENABLE_LLM_REASONING`. See
`tests/integration/test_v1_assistant.py`.

**Account-takeover detection** — `app/indicators/account_takeover.py`, `app/sender_baseline/`:
catches a real, authenticated mailbox that has been taken over. Every analyzed email (clean
ones included, even under `persist: "if_not_clean"`) records a metadata-only
`SenderObservation` (no subject/body); `app.sender_baseline.aggregation` folds one From
address's prior observations into a baseline. The rule fires only when ALL hold: established
sender (enough clean+authenticated mail over real time), this message authenticates (DMARC, or
SPF+DKIM), a real anomaly (new country from the same IP source, new sending provider, new
reply-to/return-path domain, strong timing outlier), AND a sensitive ask (payment/bank change,
invoice redirect, credential/MFA, gift cards, heavy pressure tied to a link). Anomaly alone
never fires (travellers). Anti-poisoning: only clean+authenticated observations define
"normal", and a value needs 2 sightings ≥1 day apart to count as known. Sender domain in the
account's own domains → `ACCOUNT_TAKEOVER_LATERAL`. This is the one scored use of header IPs
(see `received_chain.py`); it is gated so a forged header can only add a finding to
authenticated mail that already asks for money/credentials. See
`tests/unit/test_account_takeover.py`.

**Multi-tenancy & auth** (`app/db/models.py`, `app/auth/`): every `Account` (org/tenant) owns
many `User`s; virtually every other table (`Case`, `Incident`, `Event`, `Label`,
`AutonomyPolicy`/`AutonomyAction`, ...) is scoped to one `Account` via FK. JWT access + refresh
tokens; `app/auth/dependencies.py::get_current_user` reloads the `User` row from the DB on every
request (not just trusting token claims) so a deactivation or role change takes effect
immediately, not after TTL expiry. `require_admin` layers a role check on top.

**Config** (`app/core/config.py`): a single `Settings` dataclass, env-var-driven, loaded once at
import time as the module-level `settings` singleton. Every feature added since M2 is off by
default and documented inline with *why* — read the comment above a field before changing its
default. `.env` (gitignored) is auto-loaded via `python-dotenv`; real environment variables
always take precedence. `backend/.env.example` documents the full variable set.

**Persistence**: SQLite by default (zero-setup dev/test), Postgres via `DATABASE_URL` for real
deployments (`postgres://`/`postgresql://` URLs are rewritten to `postgresql+psycopg://` since
the app depends on psycopg v3, not the legacy psycopg2 default). Raw `.eml` uploads are stored on
disk keyed by case UUID (never in the DB — data minimization), purged after
`RAW_EMAIL_RETENTION_DAYS`.

**Routing**: every router lives in `app/api/routes/` and is included in `app/main.py`; there's no
router auto-discovery. `app/main.py`'s `lifespan` also runs the raw-email purge on startup and
(SQLite only) creates tables if missing.

## Frontend architecture

React + TS + Vite SPA, Tailwind for styling, Recharts for charts. `src/api/client.ts` is the
shared `apiFetch` wrapper every API module routes through: attaches the bearer token, and on a
401 transparently refreshes once and retries before falling back to logged-out state
(`onAuthExpired` callback, wired by `AuthContext`) — callers never handle token expiry
themselves. `src/components/` is organized by feature area (dashboard, autonomy, audit, copilot,
detections, monitoring, settings), mirroring the backend's route/domain split.

## Cross-cutting conventions worth knowing before editing

- **Registry pattern repeats deliberately**: indicators, detections, and (to a lesser extent)
  framework mappings are all "list of pure functions in a `_RULES`/`_RULES` list, run in a flat
  loop" — `app/detections/engine.py`'s docstring literally says it mirrors
  `app/indicators/engine.py`. Follow the existing pattern rather than introducing a new
  dispatch mechanism when adding a rule.
- **Feature flags default off and fail soft**: `enable_llm_reasoning`, `enable_ml_classifier`,
  `enable_copilot`, `enable_live_{slack,teams}_ingestion` all default `False`, and every one of
  them is designed so that missing config/artifacts/credentials degrades to "feature returns
  null/mock" rather than erroring. Preserve that contract for any new optional feature.
  `tests/conftest.py` pins the LLM and ML flags off for every test regardless of local `.env`.
- **Pure aggregation vs. I/O split**: modules like `app/dashboard/aggregation.py`,
  `app/baselines/aggregation.py`, and `app/autonomy/policy.py` are deliberately pure
  (no DB/network) with a thin caller elsewhere doing the I/O — makes them directly unit-testable
  without DB fixtures. Keep new aggregation/decision logic pure and push I/O to the route or a
  dedicated `store.py`.
- **One shared pipeline, not copies**: `app/analysis/email_pipeline.py` exists specifically so
  the direct-upload and inbound-webhook routes don't duplicate the parse -> indicators -> score
  -> mapping -> narrative sequence. `app/api/routes/messages.py` intentionally has its own
  smaller, separate pipeline (no `.eml`/raw-storage/LLM involved) — don't try to unify those two.
