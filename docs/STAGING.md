# Staging environment

A fully separate deployment of Cordon for testing changes before they reach customers — its own
Render backend, its own Postgres database, its own Vercel frontend, its own secrets. Nothing here
is shared with production, and pushing to `staging` never affects `main`'s deployments or data.

> **Status**: the `staging` git branch exists and is pushed. The Render/Vercel resources below
> are provisioned as a one-time setup step — see "Provisioning" if they don't exist yet in your
> account. Once they do, everything in this doc describes steady-state usage.

## Resources

| | Production | Staging |
|---|---|---|
| Backend (Render) | `aegis-backend` | `cordon-staging-backend` |
| Database (Render Postgres) | `aegis-db` | `cordon-staging-db` (plan `basic_256mb`, persistent) |
| Frontend (Vercel) | `aegis-frontend` | `cordon-staging` |
| Git branch | `main` | `staging` |
| Backend URL | `https://aegis-backend-zbcr.onrender.com` | `https://cordon-staging-backend.onrender.com` |
| Frontend URL | `https://aegis-frontend-rouge.vercel.app` | *(assigned when the Vercel project is created — see Provisioning)* |

Staging's `ENVIRONMENT` env var is `staging` (vs. production's `production`) — purely an
informational label today (nothing in the app branches on it), kept accurate for whenever that
changes.

## Secrets

Every secret staging needs is **separate from production's** — a leaked or misused staging
credential should never be able to touch real customer data or a real third-party integration:

- `JWT_SECRET_KEY` — its own randomly generated value. Staging sessions and production sessions
  are never interchangeable.
- `DATABASE_URL` — points at `cordon-staging-db`, never at `aegis-db`.
- `ANTHROPIC_API_KEY` — staging has its own (`ENABLE_LLM_REASONING=true`,
  `ENABLE_COPILOT=true`), so the AI analyst narrative and copilot can actually be tested there.
- **Deliberately left unset in staging**: `MAILGUN_WEBHOOK_SIGNING_KEY`, `INBOUND_EMAIL_DOMAIN`,
  `MICROSOFT_GRAPH_CLIENT_ID`/`MICROSOFT_GRAPH_CLIENT_SECRET`. These wire up real third-party
  systems (a real inbound-mail domain, a real Azure app registration) — sharing them between
  environments would mean a staging action could trigger a real effect (e.g. a real Microsoft
  365 tenant action) or a staging bug could interfere with production's inbound mail. Every
  feature gated by these degrades to mock/off automatically when unset (see `CLAUDE.md`'s
  "feature flags default off and fail soft" convention) — staging simply runs with those features
  in their default state, same as any fresh, unconfigured deployment.
- `ENABLE_PHISHING_SIMULATION=false` by default in staging for the same reason — see "Phishing
  simulation" below if you want to turn it on.

Actual secret *values* live only in the Render/Vercel dashboards (Environment tab) — never in
this repo, never in chat history beyond the moment you paste them in.

## Git workflow

```
main       ← production (auto-deploys backend; frontend deployed manually, see below)
staging    ← staging (auto-deploys both backend and frontend)
```

- **Day to day**: branch off `staging` (or commit straight to it) for anything you want to try
  against a real deployment. Pushing to `staging` redeploys `cordon-staging-backend` (Render
  watches the branch directly) and `cordon-staging` (Vercel's Git integration does the same) —
  no manual deploy step for staging.
- **Promoting to production**, once you've verified something on staging:
  1. Open a PR from `staging` into `main` on GitHub (or `git checkout main && git merge staging`
     if you're comfortable skipping review) and merge it.
  2. The backend redeploys automatically (Render's existing behavior for `aegis-backend` on
     `main`, unchanged by any of this).
  3. The frontend does **not** auto-deploy on `main` today (`aegis-frontend` has no Git
     integration — every production frontend deploy so far has been a manual
     `cd frontend && npx vercel --prod`, and this setup deliberately didn't change that). Run
     that command from an up-to-date `main` checkout to finish the promotion.
- Keep `staging` roughly in sync with `main` (merge `main` back into `staging` periodically, or
  just re-branch it after a promotion) so it doesn't drift into testing something already stale.

## Seeding / resetting staging data

Staging starts empty. Seed a demo account with realistic activity (cases, incidents, autonomy
actions) using the existing red-team simulation script — it talks purely over the HTTP API, so
it works against any deployment, not just localhost:

```sh
python3 scripts/attack_sim.py --base-url https://cordon-staging-backend.onrender.com \
  --email staging-demo@cordon.test --account-name "Staging Demo" --no-prompt
```

Log into the staging frontend with the same credentials to watch the data appear. Re-runnable —
each run freshens the simulated identity so detections stay deterministic.

Reset (delete all cases/incidents for that account) with:

```sh
python3 scripts/cleanup_sim.py --base-url https://cordon-staging-backend.onrender.com
```

**Not seeded — by design, not an oversight**: a verified simulation-sending domain or phishing
campaign. Domain verification (`POST /api/sim/domains/verify`) requires proving real DNS control
via a TXT record; there's no legitimate way to fake that even in staging without undermining the
actual security property it exists to enforce. To test the phishing-simulation feature in
staging, verify a real (sub)domain you control there, the same as you would in production.

## Provisioning (one-time setup)

If the resources in the table above don't exist yet:

1. **Render** (backend + database) — needs a Render API key (Account Settings → API Keys).
   Creates `cordon-staging-db` (`basic_256mb`) and `cordon-staging-backend` (Docker, `free` plan,
   tracking the `staging` branch, `backend/` as root directory — same `Dockerfile` as
   production). Env vars set per the Secrets section above. No separate migration step is
   needed: `backend/docker-entrypoint.sh` runs `alembic upgrade head` on every boot, so the
   first deploy migrates `cordon-staging-db` automatically.
2. **Vercel** (frontend) — Vercel → Add New → Project → import the `Cyberpk10/cordon` GitHub
   repo → Root Directory `frontend` → name it `cordon-staging` → after import, Project Settings →
   Git → set Production Branch to `staging`. Then set `VITE_API_BASE_URL` (Project Settings →
   Environment Variables) to the staging backend's URL, and push to `staging` to trigger the
   first deploy.
3. Once the Vercel URL is known, set the staging backend's `CORS_ALLOWED_ORIGINS` to that exact
   URL (no wildcard) so only the staging frontend can call it.
