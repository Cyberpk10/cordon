# Staging environment

A fully separate deployment of Cordon for testing changes before they reach customers — its own
Render backend, its own Postgres database, its own Vercel frontend, its own secrets. Nothing here
is shared with production, and pushing to `staging` never affects `main`'s deployments or data.

> **Status**: live. `cordon-staging-backend` + `cordon-staging-db` are provisioned and migrated;
> `cordon-staging` is deployed and seeded with a demo account. **Auto-deploy-on-push is not yet
> live for either the backend or the frontend** — both need the same one-time manual step (a
> GitHub connection only the account owner can grant) described in "Auto-deploy on push" below.
> Until then, deploy staging manually after a push (commands in that section).

## Resources

| | Production | Staging |
|---|---|---|
| Backend (Render) | `aegis-backend` | `cordon-staging-backend` |
| Database (Render Postgres) | `aegis-db` (`basic_256mb`) | `cordon-staging-db` (`basic_256mb`, persistent) |
| Frontend (Vercel) | `aegis-frontend` | `cordon-staging` |
| Git branch | `main` | `staging` |
| Backend URL | `https://aegis-backend-zbcr.onrender.com` | `https://cordon-staging-backend.onrender.com` |
| Frontend URL | `https://aegis-frontend-rouge.vercel.app` | `https://cordon-staging.vercel.app` |

Staging's `ENVIRONMENT` env var is `staging` (vs. production's `production`) — purely an
informational label today (nothing in the app branches on it), kept accurate for whenever that
changes. Staging's Render web service runs on the `free` plan (sleeps after 15 min idle — expect
a slow first request after a quiet period); its database is `basic_256mb` like production, so
seeded test data doesn't get wiped by the free Postgres plan's 30-day auto-delete.

## Secrets

Every secret staging needs is **separate from production's** — a leaked or misused staging
credential should never be able to touch real customer data or a real third-party integration:

- `JWT_SECRET_KEY` — its own randomly generated value, set once at provisioning time. Staging
  sessions and production sessions are never interchangeable.
- `DATABASE_URL` — points at `cordon-staging-db`, never at `aegis-db`.
- `ANTHROPIC_API_KEY` / `ENABLE_LLM_REASONING` / `ENABLE_COPILOT` — **not yet enabled**. Staging
  was provisioned with these off (matching a fresh deployment's defaults) pending an
  `ANTHROPIC_API_KEY` value for this environment specifically. To turn them on: set
  `ANTHROPIC_API_KEY` on `cordon-staging-backend` (Render dashboard → Environment, or via the
  API) and flip `ENABLE_LLM_REASONING`/`ENABLE_COPILOT` to `true`, then redeploy.
- **Deliberately left unset in staging**: `MAILGUN_WEBHOOK_SIGNING_KEY`, `INBOUND_EMAIL_DOMAIN`,
  `MICROSOFT_GRAPH_CLIENT_ID`/`MICROSOFT_GRAPH_CLIENT_SECRET`. These wire up real third-party
  systems (a real inbound-mail domain, a real Azure app registration) — sharing them between
  environments would mean a staging action could trigger a real effect (e.g. a real Microsoft
  365 tenant action) or a staging bug could interfere with production's inbound mail. Every
  feature gated by these degrades to mock/off automatically when unset (see `CLAUDE.md`'s
  "feature flags default off and fail soft" convention) — staging simply runs with those features
  in their default state, same as any fresh, unconfigured deployment.
- `ENABLE_PHISHING_SIMULATION=false` for the same reason — flip it on in the dashboard if you
  want to exercise that feature in staging (still gated by real DNS domain verification either
  way — see "Seeding" below).

Actual secret *values* live only in the Render/Vercel dashboards (Environment tab) — never in
this repo, never in chat history beyond the moment they're pasted in.

## Git workflow

```
main       ← production (backend auto-deploys; frontend deployed manually)
staging    ← staging (both manual for now — see "Auto-deploy on push" below)
```

- **Day to day**: branch off `staging` (or commit straight to it) for anything you want to try
  against a real deployment, then deploy manually (see "Auto-deploy on push" below) until the
  one-time GitHub connection step is done.
- **Promoting to production**, once you've verified something on staging:
  1. Open a PR from `staging` into `main` on GitHub (or `git checkout main && git merge staging`
     if you're comfortable skipping review) and merge it.
  2. The backend redeploys automatically (Render's existing behavior for `aegis-backend` on
     `main`, unchanged by any of this).
  3. The frontend does **not** auto-deploy on `main` today (`aegis-frontend` has no Git
     integration — every production frontend deploy so far has been a manual
     `cd frontend && npx vercel --prod`). Run that command from an up-to-date `main` checkout to
     finish the promotion.
- Keep `staging` roughly in sync with `main` (merge `main` back into `staging` periodically, or
  just re-branch it after a promotion) so it doesn't drift into testing something already stale.

### Auto-deploy on push (one-time step still needed — for both services)

Neither staging service actually redeploys on push yet, even though each looks fully configured
for it. This was verified directly, not assumed: `cordon-staging-backend`'s `autoDeploy`/
`branch`/`repo` fields are byte-for-byte the same shape as production's working config, but two
separate real pushes to `staging` (confirmed several minutes apart) produced zero deploys on it,
while the same pushes to `main` redeploy `aegis-backend` within seconds every time. The
difference isn't anything in the service config — it's that `aegis-backend` was originally
connected through Render's dashboard "New Blueprint" flow, which completes a GitHub App
authorization handshake for that specific repo connection; creating `cordon-staging-backend`
via the API/CLI with a bare repo URL builds and deploys fine on demand, but doesn't get that same
push-webhook wiring. The Vercel side has the analogous gap for a more visible reason: connecting
a *new* Vercel project to GitHub at all requires a one-time account-level **Login Connection**
(Vercel → Account Settings → Login Connections → GitHub) that only the account owner can grant
interactively in a browser — it isn't exposed through the CLI/API with a stored token (confirmed
by the CLI's own error: `Error: Failed to link Cyberpk10/cordon. You need to add a Login
Connection to your GitHub account first.`).

**To fix the frontend**: grant the Login Connection above once, then:

```sh
cd <a checkout of this repo, any branch>/frontend
vercel link --project cordon-staging   # if not already linked in this checkout
vercel git connect https://github.com/Cyberpk10/cordon.git
```

Then in the Vercel dashboard, Project Settings → Git → set **Production Branch** to `staging`.

**To fix the backend**: in the Render dashboard, open `cordon-staging-backend` → Settings →
"Build & Deploy" (or wherever the repo connection lives in your dashboard version) and
disconnect/reconnect the GitHub repo through the picker (rather than a pasted URL) — that's the
flow that completes the GitHub App handshake. I couldn't complete this one from the CLI/API at
all; it needs you in the dashboard.

**Until either is fixed**, deploy staging manually after a push:

```sh
# Backend — from a `staging` checkout:
render deploys create <cordon-staging-backend's service ID> --confirm

# Frontend — from a `staging` checkout, in frontend/ (or any directory rsynced from it):
vercel link --project cordon-staging   # first time only
vercel --prod
```

## Seeding / resetting staging data

Seeded already with a demo account and a realistic multi-stage attack campaign (cases, incidents,
autonomy actions) via the existing red-team simulation script — it talks purely over the HTTP
API, so it works against any deployment, not just localhost:

```sh
python3 scripts/attack_sim.py --base-url https://cordon-staging-backend.onrender.com \
  --email staging-demo@cordon.test --account-name "Staging Demo" --no-prompt
```

Log into `https://cordon-staging.vercel.app` with `staging-demo@cordon.test` (password set at
seed time) to see it. Re-runnable — each run freshens the simulated identity so detections stay
deterministic, and adds more activity to click through.

Reset (delete all cases/incidents for that account) with:

```sh
python3 scripts/cleanup_sim.py --base-url https://cordon-staging-backend.onrender.com
```

**Not seeded — by design, not an oversight**: a verified simulation-sending domain or phishing
campaign. Domain verification (`POST /api/sim/domains/verify`) requires proving real DNS control
via a TXT record; there's no legitimate way to fake that even in staging without undermining the
actual security property it exists to enforce. To test the phishing-simulation feature in
staging, verify a real (sub)domain you control there, the same as you would in production
(`ENABLE_PHISHING_SIMULATION` must also be turned on — see Secrets above).

## Re-provisioning from scratch

If these resources ever need to be recreated (e.g. after a deliberate teardown):

1. **Render**: `render postgres create --name cordon-staging-db --plan basic_256mb --confirm`,
   then `render services create --name cordon-staging-backend --type web_service --runtime docker
   --repo https://github.com/Cyberpk10/cordon --branch staging --root-directory backend --plan
   free --health-check-path /health --confirm`. Set env vars via `PUT
   https://api.render.com/v1/services/{id}/env-vars` (full array — see Secrets above for the
   list; get the DB's connection string from `GET
   https://api.render.com/v1/postgres/{id}/connection-info`). No separate migration step:
   `backend/docker-entrypoint.sh` runs `alembic upgrade head` on every boot.
2. **Vercel**: `vercel project add cordon-staging`, link a checkout of the repo's `frontend/`
   directory to it (`vercel link --project cordon-staging`), `vercel env add
   VITE_API_BASE_URL production` with the staging backend's URL, then `vercel --prod` to deploy.
   See "Auto-deploy on push" above for connecting GitHub.
3. Set the backend's `CORS_ALLOWED_ORIGINS` to the exact staging frontend URL once known.

