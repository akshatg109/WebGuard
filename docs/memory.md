# WebGuard — Project Memory

## Project Identity

Name: WebGuard

Type: Web security analysis SaaS

Primary purpose:
Provide authorized website owners and developers with a clear analysis of common web security configuration issues.

## Core Product Principle

WebGuard is a defensive analysis tool, not an exploitation framework.

## Current Technology Direction

Project root: `/home/akshat/projects/WebGuard`.

Repository layout: `frontend/` for Next.js and `backend/` for FastAPI, with
documentation in `docs/`. No monorepo orchestration tool is used at this stage.

Frontend:
- Next.js
- TypeScript strict mode
- Tailwind CSS
- shadcn/ui

Backend:
- Python
- FastAPI
- Pinned `supabase-py` async client for server-side persistence

Database/Auth:
- Supabase
- PostgreSQL
- Supabase Auth
- Dedicated Supabase project `akubhdfghktuynsncdfx` in `ap-south-1`

Deployment:
- Vercel
- Render
- Supabase

## Important Decisions

1. Use separate frontend and scanner backend.
2. Store scan history in PostgreSQL.
3. Use Supabase for authentication.
4. Scanner must implement strong SSRF protections.
5. Start with passive/safe security configuration checks.
6. Build the MVP before AI features.
7. Prioritize a premium UI because this is a portfolio project.
8. The security score must be presented as a WebGuard configuration score, not proof that a site is secure.
9. Keep documentation updated as implementation decisions evolve.
10. MVP scans execute synchronously; Redis and background workers are deferred.
11. PDF export is out of scope for MVP.
12. Scanner safeguards (URL validation, SSRF protection, timeouts, redirect and
    response-size limits, and rate limiting) are foundational MVP requirements.
13. Scoring must be deterministic, but the formula and weights must be designed
    and documented before final scoring is implemented; arbitrary weights are
    not permitted.
14. Supabase public tables require explicit grants as well as RLS; local CLI
    config disables automatic exposure of new tables.
15. Profiles are keyed directly to `auth.users.id`; scan ownership is stored in
    `scans.user_id`; child findings and technologies inherit access through
    ownership of their parent scan.
16. The FastAPI service may use a server-only Supabase secret key for controlled
    persistence after authenticating the caller and deriving ownership from a
    verified JWT. No privileged key is exposed to frontend code.
17. Next.js Supabase SSR uses `@supabase/ssr`, distinct browser/server clients,
    and Next.js 16 `proxy.ts`; future protected handlers must independently
    verify claims.
18. The Phase 3 visual system uses semantic OKLCH CSS tokens: deep blue-neutral
    surfaces, a restrained teal interaction accent, and distinct semantic
    severity colors. Components use the existing shadcn/ui Base UI primitives.
19. Dashboard, scan history, and report views use an intentionally empty preview
    data source. The UI displays em dashes and explicit no-data labels rather
    than fabricated targets, findings, or scores until a real API is connected.
20. The authenticated UI routes are `/dashboard`, `/scans`, `/scans/[id]`, and
    `/settings`, all protected by verified Supabase claims in both Next.js Proxy
    and the protected server layout. Public auth routes are `/login`, `/signup`,
    and `/auth/confirm`.
21. Phase 4A scanner networking uses aiohttp with a custom pinned-address
    resolver: every DNS answer is checked before use; each redirect is separately
    validated/resolved; automatic redirects, proxy environment variables,
    cookies, decompression, and non-GET/HEAD methods are disabled.
22. Scanner request limits are centralized in `ScannerSettings` and bounded at
    configuration load. The in-process pinning policy is defense in depth, not a
    substitute for deployment egress firewall rules.
23. The Phase 4A transport service is internal-only and returns an in-memory
    `ScanContext`; it does not invoke checks or persist scans. Phase 4B's separate
    check engine analyzes that context. There is still no public scan endpoint or
    scoring. Response bodies are bounded, and structured error serialization
    excludes target/network/header details.
24. Phase 4B findings use controlled severity/status/category enums and stable
    check IDs. The explicit registry consumes captured response data only; check
    severities are descriptive and are not numeric score weights.
25. Phase 4B covers transport observations, HSTS, CSP, X-Content-Type-Options,
    Referrer-Policy, Permissions-Policy, frame protection, and server disclosure.
    Severity is descriptive only; no scoring weights or formula are assigned.
26. Phase 4C strips Set-Cookie values into `ObservedCookie` attribute metadata
    inside the transport boundary; raw Set-Cookie fields and values are not
    carried into `ScanContext.response_headers`. Cookie findings aggregate
    observations and never expose values.
27. Mixed-content analysis is an HTMLParser pass over a maximum 256 KiB of the
    already-fetched HTTPS HTML body. It reports sanitized HTTP origins and resource
    types only; it never fetches subresources. Passive tech detection uses a
    finite evidence allowlist and a high/medium/low confidence model.

## Security Constraints

Targets must be limited to systems the user owns or is explicitly authorized to test.

Do not implement:
- credential attacks
- brute force
- destructive exploitation
- malware
- persistence
- stealth
- authentication bypass
- arbitrary command execution

## Product Tone

Professional, technical, clear, trustworthy.

Avoid marketing claims that imply a scan guarantees security.

## Current State

Phase 1 repository foundation is complete. Phase 2 created a dedicated Supabase
project and added a database migration, RLS policy tests, and SSR auth
foundations. The migration has not yet been applied to the hosted database
because database credentials are not available in the workspace. Phase 3 has
implemented a premium dark UI shell, responsive navigation, dashboard, scans
history/report layout, settings, and login/signup/confirmation UX. Phase 4A has
implemented the internal safe scanner foundation and Phase 4B has implemented a
deterministic response-context check engine, and Phase 4C has added cookie,
bounded mixed-content, and passive technology checks. No overall scoring, public
scan endpoint, persistence, or scanner-to-frontend integration exists. Live
Supabase auth still needs
project keys and hosted Auth settings in local environment configuration. The
project root is
`/home/akshat/projects/WebGuard`, with root-level documentation, a Next.js
frontend in `frontend/`, and a FastAPI service in `backend/`. Git is initialized.
The frontend has strict TypeScript, Tailwind CSS, shadcn/ui, Supabase SSR client
utilities, signup/login/logout server actions, and reusable accessible UI
primitives. FastAPI has server-only Supabase configuration and still exposes
only its health endpoint; scanner service code is not mounted as a route.

## Next Step

Wait for explicit approval before starting Phase 4D or later. Configure real Supabase
publishable keys and hosted Auth redirect/email settings to exercise live
authentication, and apply/test the database migration when database credentials
and Docker access are available. Add deployment egress firewall restrictions
before exposing scanner requests. Design scoring separately before implementing
an overall score.
