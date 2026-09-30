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
- Development interpreter pinned to Python 3.12.11 via root `.python-version`;
  backend supports Python 3.11+
- FastAPI
- Pinned `supabase-py` async client for server-side persistence

Database/Auth:
- Supabase
- PostgreSQL
- Supabase Auth
- Dedicated Supabase project `akubhdfghktuynsncdfx` in `ap-south-1`

Deployment:
- Render web service and private service
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
    persistence after Supabase Auth verifies the presented access token and loads
    its user record. Ownership comes from that verified user ID, never the request
    body. No privileged key is exposed to frontend code.
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
23. Phase 4A's transport primitive returns an in-memory `ScanContext` and does
    not itself invoke checks or persist scans. Phase 4B's separate check engine
    analyzes that context. Phase 4F composes the two behind authenticated API
    routes. Response bodies are bounded, and scanner error serialization excludes
    target/network/header details.
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
28. Phase 4D selected and documented a category-weighted, check-aware,
    capped-deduction methodology for the WebGuard security configuration score.
    Phase 4E implements it as a pure in-memory scoring module. Full category
    budgets are Transport 30, Headers 45, Cookies 15, and Content 10; exposure
    and technology are informational. `transport.http_to_https_redirect` and
    `transport.final_scheme` are diagnostic-only to avoid overlapping transport
    deductions. Exact outcome rules, coverage gates, and limitations are in
    `docs/scoring.md`.
29. The initial methodology identifier is `scoring_version = "1.0"`. Confidence
    (`complete`, `partial`, `limited`) is separate from the number; errors and
    inconclusive observations do not incur a target penalty, and limited
    evidence withholds the numeric score rather than substituting zero. Stable
    scanner check IDs are not renamed; material scoring changes get a new
    scoring version.
30. Phase 4D was documentation-only; Phase 4E adds the pure
    `backend/app/scanner/scoring.py` implementation and deterministic tests. At
    Phase 4E completion it had no database changes, public scan route, persistence,
    or UI integration. The pre-Phase-4F live schema had nullable 0–100
    `scans.score`, 11 legacy check IDs, and mismatched finding statuses.
31. Phase 4F uses Supabase Auth `get_user(token)` to verify the access token and
    derive the request owner. The synchronous pipeline stores `pending` →
    `running` → `completed`/`failed`; the score engine remains pure and is the
    single source of truth. It adds no frontend wiring, Redis, workers, queues,
    AI, or PDF work.
32. Phase 4F's additive migration retains all legacy catalog rows, seeds the 13
    canonical dotted IDs, records each explicit legacy mapping, and adds a
    user-owned `scan_check_results` table with RLS. A `SECURITY INVOKER` RPC with
    an empty search path grants execution to `service_role`, revokes public/anon/
    authenticated access, and atomically persists all child result rows and marks
    the scan complete. Earlier scan creation/running
    requests are separate transactions; a full database outage can prevent the
    failure-state update.
33. Score persistence stores scalar/version/confidence/availability in dedicated
    fields and coverage/category/deduction/unavailability metadata in JSONB.
    Per-check explanations live in `scan_check_results`, avoiding a duplicate
    list in score details. Technology confidence keeps exact low/medium/high
    labels and a numeric compatibility projection (0.4/0.7/0.9).
34. Phase 4F's process-local sliding-window rate limiter is configurable (5 scan
    creations per 60 seconds by default), but it is not a global limit across
    workers/replicas. Deployment gateway limits and outbound egress restrictions
    remain required. CORS uses exact configured origins; wildcard origins are
    rejected.
35. Phase 4G keeps scanner calls behind same-origin Next.js route handlers. The
    server verifies the existing Supabase SSR session and forwards that user's
    access token to FastAPI; the browser never receives `SCANNER_API_URL`
    or backend secrets. Scan creation is URL-only. The additive authenticated
    history endpoint filters by the verified owner and is bounded/paginated; no
    database migration or RLS change was needed.
36. Phase 4G connects dashboard/history/detail UI to real scan records, while
    retaining the synchronous lifecycle and no-polling model. No frontend test
    runner is configured, so no test dependency was added. Local browser smoke
    verified public auth pages, protected-route redirects, and an unauthenticated
    scanner API 401; authenticated rendering/live scan remains unverified without
    a backend Supabase configuration, test-user session, and explicitly
    authorized target.
37. Phase 4H adds a separate random `SCANNER_API_TOKEN` shared only by the
    Next.js server and FastAPI. FastAPI checks it in constant time on every scan
    route before verifying the user's Supabase token; missing/weak configuration
    fails closed. This credential is defense in depth, not private ingress.
    Production Supabase URLs and signup callback URLs require HTTPS; Phase 4I
    adds a narrowly constrained Render private-hostport exception for the BFF
    hop (HTTP, with no transport-encryption claim).
    FastAPI CORS remains exact-origin and rejects non-local HTTP origins/wildcards.
38. The application sets a narrow clickjacking CSP (`frame-ancestors 'none'`),
    `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, a strict-origin
    referrer policy, and production-only HSTS without `includeSubDomains` or
    `preload`; the default `X-Powered-By` response header is disabled. No broad
    script CSP or TLS-verification bypass is introduced.
39. At Phase 4H, no deployment manifest or live Vercel/Render service was
    configured. Render private services require callers on the same-region
    private network, so a Vercel BFF cannot call Render's private hostname
    directly. Render documents outbound IPs, not per-service destination/port
    egress rules. Network-level IPv4/IPv6 egress filtering and a shared/global
    rate limit remain blockers before exposure.
40. Phase 4H keeps scans synchronous but bounded: scanner overall timeout is 30
    seconds by default (hard configuration maximum 120), the Next.js BFF aborts
    upstream work after 45 seconds, and scanner API route handlers declare a
    60-second maximum. The selected deployment plan must honor that duration;
    these limits do not authorize adding workers or queues.
41. Phase 4I adds `render.yaml` for `webguard-staging-web` (Render Node web
    service) and `webguard-staging-scanner` (FastAPI Render Private Service) in
    Singapore (Render documents no Mumbai region, so Supabase calls to the
    existing Mumbai project remain cross-region HTTPS). The frontend builds with
    `npm ci && npm run build` and starts
    `next start` on `$PORT` under `NODE_ENV=production`; the backend uses Python
    3.12.11, Uvicorn on
    `0.0.0.0:$PORT`, and disabled access logs. Render's private service only has
    a TCP health check; `/health` remains a separate minimal private check.
42. Phase 4I production BFF routing uses the scanner's Blueprint-referenced
    `SCANNER_API_PRIVATE_HOSTPORT` on port 10000. The BFF fails closed in
    production when this private setting is absent/invalid and never falls back
    to a public `SCANNER_API_URL`. The private route uses HTTP. Render documents
    that same-region traffic does not traverse the public internet but does not
    establish transport encryption, so no TLS protection is claimed. Both the
    service token and verified Supabase user token remain mandatory.
43. Render's Blueprint requests staging Supabase values and exact `ALLOWED_ORIGINS`
    from the operator. A dedicated Render environment group generates and shares
    only `SCANNER_API_TOKEN` with the BFF and scanner; the Supabase secret key is
    backend-only. No staging credentials are present in the repository.
44. Render private networking solves the BFF-to-scanner private ingress
    configuration requirement when actually deployed, but Render does not
    provide destination-level scanner egress filtering through this Blueprint.
    The process-local five-per-minute limit is not global. Production deployment,
    private connectivity, authorized scans, IPv4/IPv6 egress firewall, global
    rate limits, production TLS, and provider log redaction remain unverified.
45. Phase 5 adds optional, explicit AI guidance over persisted deterministic
    findings. Model calls are not made during scan creation or report loading;
    target URLs, raw response content, cookie values, credentials, owner/scan IDs,
    and internal IPs are excluded from the bounded provider input. Structured
    output is validated, observed evidence is reconstructed from deterministic
    finding data, and AI output never changes findings or scoring. Provider
    credentials are FastAPI-only, with an OpenAI-compatible adapter and a
    per-user process-local limit. Generated content is stored separately behind
     owner-based RLS in the additive Phase 5 migration, now applied and verified
     read-only against the hosted WebGuard project. Cross-user runtime access was
     not probed because no test data or impersonated sessions were used.

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
foundations. Phase 3 has implemented a premium dark UI shell, responsive
navigation, dashboard, scans history/report layout, settings, and
login/signup/confirmation UX. Phase 4A has implemented the internal safe scanner
foundation; Phase 4B has implemented a deterministic response-context check
engine; Phase 4C has added cookie, bounded mixed-content, and passive technology
checks; Phase 4D documented the scoring methodology; Phase 4E added its pure
in-memory score calculation and explicit catalog reconciliation. Phase 4F
provides authenticated `POST /api/scans` and owner-filtered
`GET /api/scans/{id}` with synchronous checks/scoring and server-side
persistence. Its migration is applied to hosted Supabase and the hosted schema,
grants, and RLS have been verified read-only; pgTAP has not run because local
database tooling is unavailable. Phase 4G adds the bounded owner-filtered scan
history endpoint and integrates the frontend through the same-origin Next.js
BFF. The UI now renders actual dashboard/history/details and uses existing
Supabase SSR auth. Phase 4H adds a server-only BFF-to-FastAPI credential,
production HTTPS checks, security headers, environment separation, and
deployment/verification documentation. A real scan remains unverified: there is
no backend Supabase environment, test-user token/session, or explicitly
authorized target. The project root is
`/home/akshat/projects/WebGuard`, with root-level documentation, a Next.js
frontend in `frontend/`, and a FastAPI service in `backend/`. Git is initialized.
The frontend has strict TypeScript, Tailwind CSS, shadcn/ui, Supabase SSR client
utilities, signup/login/logout server actions, and reusable accessible UI
primitives. Next.js route handlers keep scanner API requests server-side. FastAPI
has server-only Supabase configuration, a minimal health endpoint, and scan
creation/history/detail routes protected by both the service credential and
verified user token. `render.yaml` prepares a private staging topology but has not
been deployed. Phase 5 adds explicit AI summary/finding routes, backend-only
provider configuration, sanitized prompts, strict response schemas, caching,
owner-checked persistence, per-user rate limits, and opt-in report UI. Its
migration is applied to hosted Supabase and was verified read-only; no live
provider request has been made.
Scanner calls must remain restricted to staging until external egress controls,
gateway/global rate limits, deployment TLS, and logging are configured and
verified.

## Next Step

Phase 5 AI guidance implementation is complete in the local codebase; stop feature
work here. The additive migration has been applied to hosted Supabase and its
schema/policies were verified read-only. pgTAP has not run because local database
tooling is unavailable; execute it in local/staging before enabling AI persistence.
No live provider credentials or provider network requests have been used. Deployment
verification, scanner egress filtering, IPv4/IPv6 destination restrictions,
global/shared rate limits, production TLS, provider log redaction, and an
authorized test scan remain outside this phase and unverified. Preserve
`scoring_version = "1.0"` unless a new versioned decision is approved. PDF,
Redis, background workers, and additional scanner checks remain out of scope.
