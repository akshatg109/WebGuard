# WebGuard

WebGuard is a defensive web security analysis platform for website owners and
developers assessing sites they own or are explicitly authorized to test. It
focuses on passive configuration checks and actionable remediation guidance.

## Repository layout

```text
WebGuard/
├── AGENTS.md
├── backend/       # FastAPI scanning service
├── docs/          # Product, architecture, design, tasks, and memory
└── frontend/      # Next.js application (TypeScript, Tailwind CSS, shadcn/ui)
```

The authenticated scanner is connected to the dashboard, scan history, and
report-detail views. Scans run synchronously for the MVP; Redis, background
workers, and PDF export are out of scope. Optional AI guidance explains existing
findings only and never changes deterministic findings or scores. WebGuard
performs passive configuration checks for sites the user owns or is explicitly
authorized to assess. Its versioned score is a configuration summary, not proof
that a site is secure.

## Requirements

- Node.js 20.9 or newer and npm
- Python 3.11 or newer

The repository pins Python `3.12.11` for pyenv users in `.python-version`.
Install that version with `pyenv install 3.12.11` if it is not already installed.

## Configuration

Use `frontend/.env.example` for `frontend/.env.local` and
`backend/.env.example` for `backend/.env`. The root `.env.example` is a combined
reference only; do not load it into either application.

`NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY`, and
`NEXT_PUBLIC_SITE_URL` are browser-visible values. Production values must use
HTTPS. `SCANNER_API_URL` is for local development only in the Render staging
configuration; production uses the server-only, Blueprint-sourced
`SCANNER_API_PRIVATE_HOSTPORT` and `SCANNER_API_TOKEN`. FastAPI keeps
`SUPABASE_SECRET_KEY`, `SCANNER_API_TOKEN`, and `ALLOWED_ORIGINS` server-side.
Never prefix a secret with `NEXT_PUBLIC_`, return it from a route, or commit a
real credential.

Generate the local/shared scanner credential with
`python -c 'import secrets; print(secrets.token_urlsafe(48))'` and copy the same
value into both app environments. Store production values in the deployment
provider's secret manager, not in this repository.

AI guidance is disabled unless the FastAPI service receives `AI_PROVIDER`,
`AI_API_KEY`, and `AI_MODEL` through its server-only environment. Supported
providers are `openai`, `openrouter`, and `openai-compatible`; custom-compatible
providers also require `AI_BASE_URL`. Use HTTPS for provider endpoints except
loopback URLs in local development. Never add an AI key to frontend variables or
the browser bundle. The default limit is 10 generations per verified user per
hour (process-local MVP limit; multiple workers need a shared/gateway limit).
The backend `.env.example` documents all optional settings.

AI requests are explicit user actions; loading a report does not call a model.
Only bounded, redacted finding data is sent to the configured provider. User and
target URLs, response bodies/headers, cookie values, and internal IPs are not
included. Generated guidance is schema-validated, stored separately from scan
results, and displayed as advisory text. The scanner's findings and score remain
authoritative. Apply `supabase/migrations/20260930120000_phase5_ai_guidance.sql`
before enabling persistence. The migration is applied to the hosted WebGuard
project and its schema, grants, and RLS policies were verified read-only. The
pgTAP suite has not been executed; run it against local/staging Supabase tooling
before enabling AI persistence.

The dedicated Supabase project is `WebGuard` (`akubhdfghktuynsncdfx`) in
`ap-south-1`. Phase 4F and Phase 5 migrations are applied to the hosted project;
catalog, grants, canonical IDs, migration history, and RLS policies were reviewed
read-only. The pgTAP suites have not been run because local Supabase CLI/Docker/
psql tooling is unavailable. Confirm hosted Auth URL/email settings before
creating a test account.

## Run locally

### Frontend

```sh
cd frontend
npm install
npm run dev
```

### Backend

```sh
cd backend
# Recreate an existing venv if it was created with a different Python version.
python -m venv --clear .venv
. .venv/bin/activate  # Windows: .venv\Scripts\activate
python -m pip install -r requirements.txt pytest
# cp .env.example .env, then populate it before starting authenticated APIs.
uvicorn app.main:app --reload --env-file .env
```

The backend health endpoint is `GET http://127.0.0.1:8000/health`. It returns
only `{"status":"ok"}` and does not require a `.env` file. Uvicorn does not
load `.env` automatically; the `--env-file .env` option is required for local
Supabase, scanner-token, and AI settings. Keep real credentials out of Git.

Configure `SCANNER_API_URL=http://127.0.0.1:8000` in `frontend/.env.local` for
local scanner requests. The browser calls same-origin Next.js routes; it does
not call FastAPI directly or provide methods, headers, credentials, or proxy
settings.

## Checks

From `frontend/`, run `npm run lint`, `npm run typecheck`, and `npm run build`.
Backend API and scanner tests are in `backend/tests/`. The frontend currently
has no configured component/E2E test runner; browser smoke checks cover the auth
pages and protected-route behavior where a test session is unavailable.

Run the backend test suite from `backend/` with `python -m pytest -q` after
installing the backend requirements and pytest in the active virtual environment.

## Supabase database

The local Supabase configuration and migrations require Docker for local
database execution. Run `npx supabase start` and `npx supabase test db` to execute
the schema migrations and RLS pgTAP tests locally. To deploy, link the CLI to the
intended staging project after obtaining its database password before applying
migrations. Do not apply staging migrations to production unintentionally. Keep
the database password and secret API key outside the repository.

## Private Render staging

The staging topology is prepared as a Render Blueprint in [`render.yaml`](render.yaml):

```text
Internet
   ↓ HTTPS
Render Next.js web service (BFF)
   ↓ same-region Render private network (HTTP; transport encryption unverified)
Render FastAPI Private Service (no public URL)
   ├── HTTPS → Supabase
   └── HTTP/HTTPS → authorized external targets
```

The BFF still requires a verified Supabase user session and sends both that
user's access token and a separate server-only scanner token. FastAPI still
verifies both. The production BFF accepts only the private service's generated
`hostport` on port 10000; it fails closed and does not fall back to a public
`SCANNER_API_URL`.

### Render service configuration

| Service | Render settings |
| --- | --- |
| `webguard-staging-web` | Web service; Node 22.22.0; region `singapore`; root `frontend`; build `npm ci && npm run build`; start `NODE_ENV=production npm run start -- --hostname 0.0.0.0 --port $PORT`; HTTP health check `/login`; plan `0.5c-512mb`. |
| `webguard-staging-scanner` | **Private Service** (`pserv`), not a public Web Service; Python 3.12.11; same `singapore` region; root `backend`; build `pip install -r requirements.txt`; start `uvicorn app.main:app --host 0.0.0.0 --port $PORT --no-access-log`; port 10000; Render TCP health check; plan `0.5c-512mb`. |

Singapore keeps the two Render services on the same private network; Render's
documented regions do not include Mumbai, so connections to Supabase in
`ap-south-1` use HTTPS over the public service egress path.

The frontend gets `SCANNER_API_PRIVATE_HOSTPORT` from the scanner service's
Blueprint `hostport` property. The shared `webguard-staging-scanner-auth`
environment group creates one random `SCANNER_API_TOKEN` and injects it only into
the two server services. Use an operator-selected **staging** Supabase project;
the repository does not assume the existing WebGuard project is staging.

### Required Render environment variables

Set the following values through the Blueprint prompts/Render secret manager,
not in Git:

| Service | Variables | Notes |
| --- | --- | --- |
| Next.js | `NEXT_PUBLIC_SITE_URL`, `NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY` | Public configuration; use the actual HTTPS staging origin and Supabase staging project. |
| Next.js | `SCANNER_API_PRIVATE_HOSTPORT` | Automatically referenced from the private FastAPI service; server-only. Do not set a public scanner URL. |
| FastAPI | `SUPABASE_URL`, `SUPABASE_PUBLISHABLE_KEY`, `SUPABASE_SECRET_KEY` | Server-only; secret/service key stays backend-only. Use staging credentials. |
| FastAPI | `ALLOWED_ORIGINS` | The exact HTTPS origin of the Render frontend (no wildcard/path); CORS is not a substitute for BFF auth. |
| Both server services | `SCANNER_API_TOKEN` | Generated in one Render environment group; minimum 32 characters and shared only by BFF and FastAPI. |

The Blueprint fixes `SCANNER_ALLOWED_PORTS=80,443,8080,8443`, the per-process
limit at 5 scans per 60 seconds, and scanner overall timeout at 30 seconds.
Other bounded scanner settings retain their application defaults. FastAPI's
`GET /health` returns only `{"status":"ok"}`. Render supports only TCP probes
for private services, so it probes the scanner listener; check `/health`
separately from inside the private network.

### Transport, limits, and deployment steps

Render's private networking routes same-region services without traversing the
public internet. Render's published documentation does **not** state that this
service-to-service traffic is encrypted. This Blueprint therefore uses HTTP for
the private BFF hop and makes no transport-encryption claim. Both authentication
factors remain mandatory; if policy requires encrypted service-to-service
transport, add and verify TLS with a trusted certificate before treating the
staging setup as suitable. Public frontend, Supabase, and HTTPS scanner-target
connections retain certificate verification. HTTP targets remain available
under the existing safe scanner policy.

Render documents regional outbound IP ranges, not destination-level egress
firewall rules. This Blueprint does not restrict scanner destinations or IPv4/
IPv6. The per-process scanner limit is not a global/shared rate limit. Therefore
this remains **PRIVATE STAGING**, not approval for unrestricted production
scanning. Keep the FastAPI service private and do not run scans until an
explicitly authorized staging target and credentials are available.

Render does not document a conflicting HTTP request-duration cap in the
references reviewed for this phase. The application limits remain unchanged:
30-second scanner deadline, 45-second BFF abort, and 60-second Next.js route
maximum. Confirm actual request duration on the deployed plan before use.

1. Create/choose a staging Supabase project; apply reviewed schema migrations and
   configure its Auth site/redirect URLs for the actual HTTPS staging frontend.
2. Validate the manifest: `render blueprints validate render.yaml` (Render CLI
   v2.7.0 or later).
3. In Render, create a **Blueprint Instance** from this repository and select
   `render.yaml`. Supply the `sync: false` staging values. Set
   `NEXT_PUBLIC_SITE_URL` and `ALLOWED_ORIGINS` to the exact frontend origin.
4. After initial deployment, verify Render reports the scanner service as a
   Private Service and that no public FastAPI URL exists. Test private DNS,
   connectivity, both auth factors, logs, and timeouts before any authorized
   staging scan.
5. Later manual service deploys can use
   `render deploys create <SERVICE_ID> --wait` after authenticating the Render
   CLI; ordinary linked-branch pushes use Render's configured auto-deploy.

### Phase 4I deployment checklist

**DONE — configuration prepared in this repository**

- Render Next.js web service configuration and health path
- Render FastAPI **Private Service** configuration and TCP health check
- Private BFF → FastAPI hostport routing configuration
- Server-side secret wiring (actual secret values are operator-supplied)
- HTTPS settings for the public frontend/Supabase and unchanged target TLS verification
- Code-level logging review; Uvicorn access logs are disabled for the scanner

**NOT YET VERIFIED — requires Render/Supabase infrastructure and authorized test inputs**

- Production/staging deployment and actual private network connectivity
- External authorized-target scan
- Scanner egress firewall and IPv4/IPv6 destination restrictions
- Global/shared rate limiting
- Production TLS certificate verification
- Production provider-log redaction

See [docs/architecture.md](docs/architecture.md#phase-4i--render-private-staging-preparation)
for the security model and detailed verification gates. No live deployment,
private connectivity, or scan has been fabricated or claimed.

## Product and security scope

See `docs/prd.md` for MVP requirements, `docs/architecture.md` for service
boundaries, and `docs/design.md` for UI direction. WebGuard is not an
exploitation framework and does not guarantee that a scanned site is secure.
# WebGuard
