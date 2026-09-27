# WebGuard — Project Architecture

## 1. Architecture Overview

WebGuard uses a web frontend, a dedicated scanning API, and Supabase/PostgreSQL.

The single project root is `/home/akshat/projects/WebGuard`. The Next.js application
lives in `frontend/`, the FastAPI scanning service lives in `backend/`, and the
project documentation lives in `docs/`. This is a simple two-application
repository; do not add monorepo orchestration tooling at this stage.

The frontend uses TypeScript strict mode, Tailwind CSS, and shadcn/ui. Supabase
provides authentication and PostgreSQL persistence.

The dedicated Supabase project is `WebGuard` (`akubhdfghktuynsncdfx`) in Mumbai
(`ap-south-1`). Database changes are maintained as SQL migrations under
`supabase/migrations/`; the schema/RLS migration must be applied to the hosted
project before the Data API is usable. No database credentials are checked in.

```text
Browser
   |
   v
Next.js Application
   |
   +---- Supabase Auth
   |
   +---- Supabase/PostgreSQL
   |
   v
FastAPI Scanning Service
   |
   +---- HTTP analysis
   +---- Header checks
   +---- Cookie checks
   +---- TLS checks
   +---- Technology detection
   |
   v
Scan Results
   |
   v
Supabase/PostgreSQL
```

## 2. Recommended Stack

### Frontend
- Next.js
- TypeScript
- Tailwind CSS
- shadcn/ui or equivalent accessible component system
- Recharts or equivalent for analytics

### Backend
- Python
- FastAPI
- aiohttp (selected for a custom resolver that pins validated DNS answers)
- Pydantic
- cryptography / appropriate TLS tooling where required

### Database/Auth
- Supabase
- PostgreSQL
- Supabase Auth

### Deployment
- Vercel for Next.js
- Render or equivalent for FastAPI
- Supabase for database/auth

### Later
- Redis
- background worker
- scheduled jobs

### MVP execution model

MVP scans execute synchronously in the FastAPI request flow. Redis and background
workers are intentionally deferred until observed scan duration or load requires
them. Synchronous execution does not relax any security controls.

## 3. Frontend Responsibilities

The frontend handles:
- authentication UI
- dashboard
- scan creation
- scan status
- results visualization
- finding details
- scan history
- settings
- report download initiation

The frontend must not contain scanner secrets or perform privileged server-side scanning directly from the browser.

## 4. Backend Responsibilities

FastAPI handles:
- target validation
- SSRF protections
- safe HTTP requests
- scan orchestration
- individual security checks
- scoring
- normalization of results
- scan status
- controlled persistence

### Phase 4A — secure scanner foundation

Scanner code lives under `backend/app/scanner/` and is independent of Supabase
models and persistence. `ScannerService.fetch()` accepts an HTTP(S) URL and
`GET`/`HEAD` only, returns an internal `ScanContext`, and performs no security
checks. There is no public scan endpoint in Phase 4A.

Target handling follows this sequence:

1. Parse and normalize the URL without doing network I/O. Reject missing or
   unsupported schemes, userinfo, control characters, malformed escapes,
   ambiguous numeric IPv4 forms, local hostnames, non-web ports, and private or
   reserved IP literals. IDNs are normalized with IDNA; a trailing root dot is
   canonicalized and fragments are dropped because they are not sent in HTTP.
2. Resolve each hostname once with the system resolver under a DNS timeout.
   Inspect every A/AAAA answer and reject the whole set if any address is not
   globally routable. This includes loopback, RFC1918, link-local, CGNAT,
   multicast, unspecified, documentation, benchmarking, transition, and other
   reserved ranges, plus known metadata destinations.
3. Pin the validated address set into an aiohttp resolver for that single
   request. The connector cannot independently re-resolve the host; DNS caching
   and keep-alive are disabled, environment proxies are ignored, and TLS still
   validates the original hostname/SNI. A fresh resolution and pin are required
   for every redirect hop.
4. Disable automatic redirects. The service records each hop, enforces a
   redirect count and loop check, canonicalizes and validates every destination,
   then resolves and checks its complete address set before connecting.
5. Send only controlled `GET`/`HEAD` requests with a WebGuard User-Agent,
   `Accept`, and `Accept-Encoding: identity`. No user headers, cookies, auth,
   browser impersonation, form submissions, or state-changing methods are used.

The aiohttp client is streaming, has per-operation connect/read timeouts, a
bounded request/overall deadline, connector/semaphore limits, and an explicit
response byte cap and response-header count/line/field caps. Declared oversized
bodies fail before reading; unknown-length bodies stop after at most one byte
beyond the cap. Response decompression is disabled so compressed input cannot
expand without bound; `Content-Encoding` is captured for a future bounded
decoder. Response headers/status are captured before body reading, including as
internal partial context on an oversize error.
Error serialization deliberately excludes URLs, addresses, headers, cookies,
exception strings, and other sensitive details.

Set-Cookie fields are an exception to raw response-header retention: during the
transport response-head normalization they are parsed independently into
`ObservedCookie` attributes, and the cookie value is discarded before
`ResponseHead`/`ScanContext` is constructed. The ordinary normalized header list
does not contain raw Set-Cookie values.

`ScannerSettings.from_environment()` reads scanner allowlists and limits. The
development defaults are HTTP/HTTPS, ports 80/443/8080/8443, five redirects,
1 MB response bodies, 10 concurrent scanner slots, 3-second DNS/connect/write,
8-second read, and 30-second overall deadlines. Configuration ranges are
validated and capped. aiohttp has no separate socket-write timeout option; the
write budget is included in the request's total deadline. Since requests have
no body and only a small fixed header set, there is no unbounded upload path.

The pinning policy prevents DNS rebinding between validation and the HTTP
connection inside this process. It cannot control transparent network routing,
host-level NAT, or infrastructure beyond the process; deployments should also
use outbound firewall/egress rules that deny private, link-local, and metadata
destinations. The scanner foundation is internal-only until a future API adds
authentication, authorization, rate limiting, and request quotas.

### Phase 4B — core check engine

`backend/app/scanner/findings.py` defines controlled `Severity`, `FindingStatus`,
and `FindingCategory` enums plus a deterministic JSON-friendly finding model.
Findings use stable IDs, a query-stripped affected URL, an observed summary,
why-it-matters text, remediation, and structured evidence. Severity describes a
finding; it is not converted to a numeric weight and does not imply an overall
score.

`checks/base.py` defines the check interface and shared response/error behavior.
`checks/registry.py` uses an explicit fixed-order registry (no filesystem import
magic) and isolates a check exception as a safe `error` finding. Header helpers
preserve duplicate values and compare names case-insensitively.

Current checks observe final HTTPS and final URL scheme, recorded HTTP-to-HTTPS
redirects, HSTS, CSP, X-Content-Type-Options, Referrer-Policy, Permissions-Policy,
frame protection via X-Frame-Options/CSP `frame-ancestors`, and Server/
X-Powered-By disclosure. Checks use only captured `ScanContext` data and perform
no network requests. Header presence is not proof that an application is secure;
CSP parsing flags limited observed constructs, HSTS `preload` is recorded without
claiming preload eligibility, and server identification is not inherently a
vulnerability. Cookie analysis, body-based mixed-content detection, and
technology detection were deferred from Phase 4B; the first three are
implemented in Phase 4C below. Scoring and API/frontend integration remain
deferred.

The check registry is not wired into `ScannerService`, a route, Supabase, or the
frontend. No score formula or numeric severity weight is defined in Phase 4B.

### Phase 4C — extended passive checks

The check registry includes three additional checks. `cookies.security_attributes`
consumes `ScanContext.response_cookies`, an attribute-only normalization created
when the Phase 4A transport captures each `Set-Cookie` header. Raw cookie values
are discarded before response metadata enters `ScanContext`; normalized cookie
attributes are kept separately from the ordinary response-header list. Findings aggregate
counts and names for observable issues and include `Secure`, `HttpOnly`,
`SameSite`, domain/path scope, `Max-Age`, `Expires`, and `__Host-`/`__Secure-`
prefix observations. `HttpOnly` is advisory only for cookie names that suggest
session/authentication use; a name heuristic is not treated as proof of purpose.
Missing `SameSite` is framed as review guidance, and Secure requirements are
applied only when the final response is HTTPS. `SameSite=None` without Secure is
reported separately. No cookie values are retained in findings or serialized.

`content.mixed_http_resources` inspects only a complete captured HTML/XHTML body
from an HTTPS response. It uses the standard-library HTML parser to inspect
resource-bearing attributes (scripts, stylesheets, images, frames, media, and
related link elements); comments, script text, plain text, and ordinary anchor
links are not treated as loaded resources. Inline CSS `url(...)`, `srcset`, and
non-HTML resource syntax are not analyzed. Inspection is capped at 256 KiB, with
bounded result counts. Evidence contains resource categories and HTTP origins
only, omitting userinfo, paths, queries, and fragments. Active resource types
receive a higher severity than passive image/media references, but no subresource
is fetched and no crawling occurs.

`technology.passive_indicators` returns separate internal `Technology` models
for a conservative allowlist of response-header markers, generator metadata,
framework/CMS HTML markers, and recognized static-asset paths within the same
bounded captured HTML prefix. Confidence is `low`, `medium`, or `high`: a single
weak React marker is low; one explicit recognized marker is medium; corroborating
independent markers can raise confidence to high. Signal names, not response-body
snippets or cookie values, are stored as evidence. This is passive identification,
not verification or active fingerprinting.

The Phase 4C checks add no network requests and do not alter the Phase 4A request
path. Cookie observations, mixed-content references, and technology results
remain in memory only. Overall scoring, findings persistence, public API
exposure, and frontend integration remain later work.

Before persistence is connected, reconcile finding serialization with the
existing Phase 2 `findings.status` constraint (`passed`/`failed` versus the
internal `pass`/`fail`/`warn` vocabulary) and decide how the textual
`TechnologyConfidence` values map to the existing numeric
`technologies.confidence` column. Phase 4C intentionally makes no schema changes.

## 5. Database Model

### profiles
- id (primary key and foreign key to `auth.users.id`)
- email
- display_name
- created_at
- updated_at

### scans
- id
- user_id
- target_url
- normalized_url
- status
- score
- started_at
- completed_at
- duration_ms
- error_message
- created_at

### findings
- id
- scan_id
- check_id
- title
- severity
- status
- description
- evidence
- recommendation
- created_at

Findings and technologies belong to a scan; their policies authorize access by
checking that the related scan belongs to `auth.uid()`. Clients can read these
rows but cannot create or alter scanner results.

### scan_checks
Optional normalized check metadata:
- check_id
- name
- category
- description
- default_severity
- remediation

### technologies
- id
- scan_id
- name
- category
- confidence

Authenticated clients can read their own scans and delete their own scans.
FastAPI is responsible for scan/result writes using a server-only Supabase
secret key through the pinned `supabase-py` async client after verifying the
request JWT and deriving `user_id` from its verified `sub` claim. Never trust a
caller-supplied user ID. Profiles permit
owner-only read/insert/update. The global `scan_checks` catalog is read-only to
authenticated users. Anonymous Data API access is not granted.

RLS is enabled on all five public tables. Explicit table grants complement the
row policies: `anon` receives no table privileges; `authenticated` receives only
the operations described above; the backend `service_role` receives persistence
privileges and bypasses RLS, so its secret key must remain server-only. RLS
policies do not rely on editable user metadata.

### Next.js authentication integration

Use `@supabase/ssr` with distinct browser and request-scoped server clients.
Next.js 16 uses `src/proxy.ts` (not the deprecated `middleware.ts`) to refresh
sessions and gate `/dashboard/*`, `/scans/*`, and `/settings/*` routes using
verified `auth.getClaims()`.
Email signup confirmation exchanges its one-time code in `/auth/confirm` before
redirecting to the protected application route.
Protected server pages/actions must also verify claims themselves; Proxy is not
the sole authorization boundary. Signup/login/logout server actions back the
accessible Phase 3 auth screens; settings exposes the verified profile email and
session sign-out without profile mutations.

The Phase 3 UI routes are `/dashboard`, `/scans`, `/scans/[id]`, and `/settings`.
They render under a shared protected layout that calls `requireUser()` and passes
only the verified user ID/email needed by the shell. `/login`, `/signup`, and
`/auth/confirm` are public routes. Scan history/report views currently consume an
empty, separately defined preview dataset; they do not fetch Supabase scan data
or present fabricated scan outcomes. The UI's score and finding components are
placeholders only, with no scoring logic or target requests.

### Environment variable boundaries

- Browser-safe: `NEXT_PUBLIC_SUPABASE_URL`,
  `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY`, and `NEXT_PUBLIC_SITE_URL`. The first
  two are public project values; RLS enforces data access.
- Server-only: `SUPABASE_SECRET_KEY` (privileged and RLS-bypassing), scanner
  service token, and FastAPI configuration. Never prefix privileged values with
  `NEXT_PUBLIC_` or return them from server code.

The local CLI config disables automatic exposure of new tables. Every required
Data API privilege is explicitly granted in the migration after RLS is enabled.

## 6. Security Boundaries

### Browser → Next.js
Use authenticated sessions and server-side validation.

### Next.js → FastAPI
Use authenticated service communication. Never trust user-provided user IDs.

### FastAPI → Target
This is the highest-risk boundary.

Implement:
- URL parsing
- scheme allowlist
- DNS/IP validation
- private/reserved address protection
- redirect validation
- timeout
- response size limits
- concurrency limits
- rate limits

These controls are foundational scanner requirements and must be present in the
MVP implementation, not deferred to production hardening.

Phase 4A implements URL, DNS/IP, request, redirect, timeout, and response-size
controls only. Individual security checks, scoring, scan persistence, and API
routes remain later work.

## 7. API Design

### POST /api/scans
Create a scan.

Input:
```json
{
  "url": "https://example.com"
}
```

### GET /api/scans/{scan_id}
Get scan status/result.

### GET /api/scans
Get current user's scan history.

### GET /api/scans/{scan_id}/findings
Get findings.

### GET /api/scans/{scan_id}/report
Generate/download report.

## 8. Scan Lifecycle

```text
CREATED
   |
   v
VALIDATING
   |
   v
SCANNING
   |
   +----> FAILED
   |
   v
COMPLETED
```

## 9. Scoring

The score should be transparent and deterministic.

Recommended initial model:
- deterministic score based on documented check outcomes and impact
- the exact formula and any weights require an explicit scoring-design decision
  before final scoring is implemented; do not invent arbitrary weights
- score is capped between 0 and 100 once the formula is defined

The UI must explain that the score is a WebGuard configuration score, not a guarantee that a website is secure.

## 10. Error Handling

Return stable error structures.

Example:
```json
{
  "error": {
    "code": "INVALID_TARGET",
    "message": "The target URL is invalid or not allowed."
  }
}
```

Do not expose internal stack traces to users.

## 11. Testing Strategy

### Frontend
- component tests
- form validation tests
- basic end-to-end flows

### Backend
- unit tests for every security check
- URL validation tests
- SSRF protection tests
- API tests
- scoring tests

### Integration
- authenticated scan creation
- completed scan retrieval
- history retrieval

## 12. Deployment Architecture

```text
                Internet
                   |
          ┌────────┴────────┐
          |                 |
       Vercel             Render
          |                 |
     Next.js App        FastAPI
          |                 |
          └────────┬────────┘
                   |
                Supabase
             PostgreSQL/Auth
```
