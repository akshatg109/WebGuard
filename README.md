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

Scans are synchronous for the MVP. Redis and background workers are deferred.
PDF export is out of scope for MVP. Target validation, SSRF protections, network
timeouts, redirect and response-size limits, and rate limiting are foundational
scanner requirements. The security score will be deterministic; its formula and
weights must be designed and documented before implementation.

## Requirements

- Node.js 20.9 or newer and npm
- Python 3.11 or newer

The repository pins Python `3.12.11` for pyenv users in `.python-version`.
Install that version with `pyenv install 3.12.11` if it is not already installed.

## Configuration

Use `.env.example` as a reference and copy only the matching values into
`frontend/.env.local` and `backend/.env`. `NEXT_PUBLIC_SUPABASE_URL`,
`NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY`, and `NEXT_PUBLIC_SITE_URL` are
browser-safe values. The
Supabase secret key and scanner token are server-only and must never be prefixed
with `NEXT_PUBLIC_` or sent to the browser. The checked-in keys are placeholders;
do not commit real credentials.

The dedicated Supabase project is `WebGuard` (`akubhdfghktuynsncdfx`) in
`ap-south-1`. The schema migration is in `supabase/migrations/`; the project
still needs the migration applied and its Auth URL/email settings configured.

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
python -m pip install -r requirements.txt
uvicorn app.main:app --reload
```

The backend health endpoint is `GET http://127.0.0.1:8000/health`. It does not
require a `.env` file. To load optional backend settings locally, copy
`backend/.env.example` to `backend/.env` and start Uvicorn with
`--env-file .env`. Keep real credentials out of Git.

## Checks

From `frontend/`, run `npm run lint`, `npm run typecheck`, and `npm run build`.
The scanner API will gain security and integration tests as its capabilities are
implemented.

## Supabase database

The local Supabase configuration and migrations require Docker for local
database execution. Run `npx supabase start` and `npx supabase test db` to execute
the schema migrations and RLS pgTAP tests locally. To deploy, link the CLI to the
WebGuard project after obtaining its database password, then run
`npx supabase db push`. Keep the database password and secret API key outside the
repository.

## Product and security scope

See `docs/prd.md` for MVP requirements, `docs/architecture.md` for service
boundaries, and `docs/design.md` for UI direction. WebGuard is not an
exploitation framework and does not guarantee that a scanned site is secure.
# WebGuard
