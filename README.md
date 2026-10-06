# Cordon

Cordon is a defensive, AI-assisted email and identity security platform: it detects phishing
and business email compromise, correlates intrusion and data-exfiltration signals across user
activity, and turns both into audit-ready compliance evidence — with human-approved autonomous
response in the loop, not automatic action.

Cordon analyzes and (opt-in, policy-gated) contains. There is no exploitation and no destructive
action anywhere in its action catalog.

## Core capabilities

- **Three-layer phishing detection** — a deterministic, rule-based indicator engine (sender
  spoofing, look-alike/homoglyph domains, credential and payment-fraud language, link and
  attachment risk, per-account sender-history anomalies, threat-intel feed matches) fuses with
  an optional ML classifier and an optional LLM analyst assessment (a human narrative plus a
  bounded, structured intent signal). Both optional layers can only nudge the score within a
  hard cap, and the LLM signal is additive-only (it can raise a score, never lower one) — the
  deterministic rule-based verdict can never be overridden or pushed to safe by either.
- **AI-generated content detection** — flags phishing text that reads as LLM-authored, a
  growing share of real-world lures.
- **Intrusion & data-exfiltration detection** — per-actor behavioral baselines (UEBA) plus
  cross-actor correlation catch brute force, impossible travel, anomalous locations, mass file
  access, privilege escalation, and both single-event and slow/cumulative exfiltration.
- **Early-warning sensor** — a continuously decaying per-actor threat level that corroborates
  weak signals across the kill chain (delivery → access → collection → exfiltration) to flag an
  attack *forming*, before any single signal alone would justify an incident.
- **Phishing simulation & human-risk training** — authorized internal campaigns with
  click/report tracking and automatic, targeted training recommendations for repeat high-risk
  recipients.
- **Autonomous response** — a policy engine (auto-execute / require-approval / skip) drives a
  small, fixed, non-destructive action catalog (quarantine, block sender domain, disable
  session, flag for review) through a real Microsoft Graph connector or a safe mock, gated by a
  blast-radius rate limit. Irreversible actions always require human approval.
- **Compliance mapping** — every finding maps to MITRE ATT&CK, NIST CSF, ISO 27001, and SOC 2
  controls, with continuous control monitoring that tracks evidence freshness and drift over
  time, and generates audit evidence packs on demand.
- **Analyst copilot** — a natural-language assistant that answers questions over an account's own
  cases, incidents, and risk posture — grounded in already-computed data, never a free-standing
  source of truth.
- **Threat-intelligence enrichment** — cross-references senders, links, and event source IPs
  against a multi-feed threat-intel snapshot.

## Architecture

| Component | Stack | Role |
| --- | --- | --- |
| `backend/` | FastAPI (Python 3.11+), SQLAlchemy, Postgres (prod) / SQLite (dev) | The runtime API — detection, scoring, autonomy, compliance |
| `frontend/` | React, TypeScript, Vite, Tailwind, Recharts | The analyst-facing SPA |
| `ml/` | pandas, scikit-learn | Offline corpus/training pipeline that publishes the classifier Stage 1 consumes |
| `site/` | Next.js | The public marketing site |

Deployed as backend (Render) + frontend (Vercel); see [DEPLOYMENT.md](DEPLOYMENT.md) for the
full walkthrough. Every optional/network-dependent feature (LLM reasoning, ML classifier, real
Graph autonomy, live chat ingestion) defaults off and degrades gracefully — nothing exotic is
required to run Cordon locally or in production.

## Testing & red-teaming

- **Automated test suite** (`pytest`, `backend/tests/`) — unit and security tests, including a
  dedicated cross-tenant isolation and prompt-injection suite, run fully offline and
  deterministically against an in-memory database.
- **Daily real-world red-team suite** (`scripts/attack_sim_realworld.py`) — the commodity and
  criminal attacks that actually breach under-resourced organizations: credential phishing,
  BEC/wire fraud, account takeover, password spraying, a full ransomware precursor chain, and
  commodity malware lures. Every scenario is expected to be caught; the hard bar is zero false
  positives. Runs against an isolated, single-use local account so results can never be
  contaminated by a prior run, and gates the daily green.
- **Monthly nation-state/APT ceiling test** (`scripts/attack_sim_phase4.py`) — elite-tier
  tradecraft engineered to probe the honest limits of today's detection. Most of it is expected
  to get through; it's tracked for visibility and does not gate daily green.

## Getting started

### Backend

```sh
cd backend
python3.11 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest -v
uvicorn app.main:app --reload
```

Zero-config by default: a local SQLite database is created automatically. Point `DATABASE_URL`
at Postgres (see `docker-compose.yml`) for parity with production.

### Frontend

```sh
cd frontend
npm install
npm run dev
```

The dev server proxies `/api` to `http://localhost:8000`.

### ML pipeline

```sh
cd ml
python3.11 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python -m aegis_ml.cli build --skip-download
python -m aegis_ml.train
```

See `ml/models/CARD.md` for the published model's documentation.

## Configuration

Every optional feature (LLM reasoning, ML classifier, copilot, live chat ingestion, real
Microsoft Graph autonomy, phishing-simulation sending) is off by default and documented inline
in `backend/app/core/config.py`, with `.env.example` listing the full variable set. Never commit
`.env` or any real API key/credential — both are gitignored, and this repo never has them
committed.

See [DEPLOYMENT.md](DEPLOYMENT.md) for production deployment and [CLAUDE.md](CLAUDE.md) for a
deeper architectural tour of the codebase.
