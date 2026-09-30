# WebGuard — Project Architecture

## 1. Architecture Overview

WebGuard uses a web frontend, a dedicated scanning API, and Supabase/PostgreSQL.

The single project root is `/home/akshat/projects/WebGuard`. The Next.js application
lives in `frontend/`, the FastAPI scanning service lives in `backend/`, and the
project documentation lives in `docs/`. This is a simple two-application
repository; do not add monorepo orchestration tooling at this stage.

The frontend uses TypeScript strict mode, Tailwind CSS, and shadcn/ui. Supabase
provides authentication and PostgreSQL persistence.

The existing Supabase project is `WebGuard` (`akubhdfghktuynsncdfx`) in Mumbai
(`ap-south-1`). Staging must use an operator-selected Supabase project and its
server-side credentials; this repository does not assume that the existing
project is a staging project. Database changes are maintained as SQL migrations
under `supabase/migrations/`; no database credentials are checked in.

```text
Browser
  | public HTTPS; same-origin requests only
  v
Render Next.js web service (BFF)
  | server-only SCANNER_API_TOKEN + verified user access token
  | Render same-region private network; HTTP to Blueprint-sourced hostport
  v
Render FastAPI Private Service (no public URL)
  | verify both credentials; per-user rate limit
  | Phase 4A SSRF validation, DNS pinning, redirect revalidation
  | outbound; no destination-level Render firewall configured
  +-- HTTPS / server-only Supabase secret --> Supabase Auth / PostgreSQL
  +-- HTTP/HTTPS --> authorized public target
  +-- HTTPS / server-only provider key --> configured OpenAI-compatible AI provider
      only after an explicit, authenticated generation request
```

The Render service definitions and private hostport reference are prepared in
`render.yaml`; they are **not deployed or connectivity-verified**. Render private
networking keeps the BFF-to-scanner route off the public internet, but Render's
published documentation does not establish transport encryption for this hop.
Treat it as HTTP without verified in-transit encryption. Both scanner service
authentication and verified Supabase user authentication remain required.
Render private networking does not provide the required destination-level scanner
egress firewall.

This is private-staging preparation, **not a statement that services are
deployed, private connectivity is verified, egress filtering exists, or global
rate limits are configured**. The deployment gates are recorded below.

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
- Render web service for Next.js and BFF
- Render Private Service for FastAPI scanner
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
- optional AI explanations/summaries of existing findings (never scan or score)

### Phase 5 — opt-in AI guidance

AI is an advisory layer over the persisted deterministic scan bundle. There are
no model calls during scan creation or report loading. An authenticated user
explicitly requests a summary or one finding explanation through same-origin
Next.js BFF routes; FastAPI verifies both the scanner service credential and the
Supabase access token, checks scan ownership (and finding-to-scan membership),
then applies a per-user generation limit. Cached output is returned without a
provider call unless the user explicitly regenerates it.

The provider receives only a bounded finding projection: stable check ID,
controlled category/status/severity, deterministic finding text, sanitized
evidence, and limited per-check scoring explanation. Target/affected URLs, owner
and scan IDs, raw response headers/bodies, cookie values, credentials, and
internal IPs are excluded. Evidence remains untrusted data in a separate JSON
user message; static system instructions prohibit following embedded directions,
scanning, inventing evidence, or changing findings/score. Provider output is
validated against strict field/length contracts. The returned "observed
evidence" field is reconstructed from deterministic scanner data, not model
text. Text is rendered as text, never HTML.

Provider input is limited to 50 findings and 64 KiB of serialized structured
data. The default budget is 10 generations per verified user per hour; this MVP
limiter is process-local, so a multi-worker deployment also needs a shared or
gateway limit.

Provider settings and keys exist only in the FastAPI environment. AI is disabled
when settings are absent/invalid, while deterministic scanning and reports
continue to work. Provider calls use a bounded timeout/response size and do not
follow redirects. The migration
`20260930120000_phase5_ai_guidance.sql` stores summaries and finding explanations
in separate tables with scan ownership RLS, explicit grants, and versioned input
hashes/prompt versions. It is additive and has **not** been applied to the hosted
Supabase project. AI persistence failures on report reads degrade to an empty AI
state without hiding deterministic scan results.

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
destinations. Phase 4A itself exposed no route; Phase 4F mounts only the
authenticated, rate-limited scan API described below. The deployment egress
firewall remains a required control, not a substitute supplied by application
validation.

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

At the completion of Phase 4B, the registry was not wired into `ScannerService`,
a route, Supabase, or the frontend. No score formula or numeric severity weight
was defined in Phase 4B.

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
remained in memory until the Phase 4F persistence/API integration.

Before persistence is connected, reconcile finding serialization with the
existing Phase 2 `findings.status` constraint (`passed`/`failed` versus the
internal `pass`/`fail`/`warn` vocabulary) and decide how the textual
`TechnologyConfidence` values map to the existing numeric
`technologies.confidence` column. Phase 4C intentionally makes no schema changes.

### Phase 4D — security scoring design (documentation only)

`docs/scoring.md` records the Phase 4D scoring decision: a category-weighted,
check-aware, capped-deduction WebGuard security configuration score, with
documented check-specific deductions, explicit handling for applicability and
partial/error evidence, separate confidence, and methodology version `1.0`.
Finding severity remains descriptive and is not a numeric weight. Stable dotted
scanner check IDs are retained; the older seeded database check IDs require an
explicit mapping before persistence.

Phase 4D changes documentation only. It adds no scoring function, production
weight, score field, migration, endpoint, or frontend behavior. Scoring
implementation and integration are deferred to a separately approved next
phase.

### Phase 4E — pure scoring engine and catalog reconciliation

`backend/app/scanner/scoring.py` implements `score_findings()` as a deterministic
pure analysis of canonical `Finding` results. Its single methodology constant is
`SCORING_VERSION = "1.0"`; the check-aware point allocations, check versions,
status/evidence rules, capped aggregations, legitimate not-applicable rules,
coverage gates, half-up rounding, and confidence are kept in the scoring module.
It makes no network/filesystem calls and does not alter the Phase 4A–4C scanner
checks.

The in-memory catalog includes all 13 current dotted check IDs: 9 score-bearing,
the two diagnostic transport IDs at zero weight, and the informational exposure
and technology checks at zero weight. The 11 legacy `scan_checks` IDs have
explicit one-to-one correspondence metadata; canonical dotted IDs are never
renamed or silently inferred from the legacy IDs. `server_header` is kept as
legacy catalog history; the canonical `exposure.server_headers` category is
`exposure`. Coverage requires 60 applicable points plus 80% point and check-count
coverage. Result metadata includes score availability, confidence, category
breakdown, and deterministic check-level reasons. See `docs/scoring.md` for the
reconciliation table and exact behavior.

At the completion of Phase 4E, there was no Supabase migration, score persistence,
scan execution route, public API, or frontend wiring. Phase 4F now performs the
separately approved backend integration in the migration and pipeline below.
Legacy catalog rows remain intact; canonical IDs are never translated through
runtime aliases.

### Phase 4F — authenticated synchronous scanner pipeline

`POST /api/scans` accepts exactly `{ "url": "https://example.com" }`; extra
fields are rejected, the raw body is capped at 32 KiB, and validation errors
never echo request content. A bearer
access token is required. The backend calls the configured Supabase Auth
`get_user(token)` operation, which validates the JWT against the project's Auth
service and loads its user. The verified Auth user UUID—not any request-body
value—is the `scans.user_id`. Missing, malformed, expired, invalid, or unverifiable
credentials are rejected; Auth-provider outages are reported as service
unavailability rather than treating a credential as valid. Password auth is not
implemented in FastAPI.

The route validates the target with Phase 4A's no-network URL parser before
creating a record, then `ScannerService.fetch()` repeats validation and applies
DNS/IP checks, pinned addresses, allowed ports, safe fixed GET behavior, bounded
timeouts/response size, and validation of every redirect. It does not accept
headers, methods, proxies, credentials, custom resolvers, or arbitrary IP
configuration. The check registry and `score_findings()` run only over the
captured `ScanContext`; the scoring module remains the single source of truth.

Each accepted request creates a `pending` row, marks it `running`, and executes
synchronously in the request. Scanner failure produces a `failed` row with a
controlled error code/message. On success, findings, passive technologies, all
13 canonical check results, and the score are sent to the restricted
`public.persist_completed_scan` Postgres RPC. That `SECURITY INVOKER` function
uses an empty search path, verifies scan ownership/lifecycle and complete
canonical inventory, and atomically inserts children and changes the scan to
`completed`. Execute is granted to `service_role`, while `PUBLIC`, `anon`, and
`authenticated` are revoked; the function owner retains normal owner privileges.
It has the existing required table grants and does not elevate privileges. Scan creation/running updates
and completion are separate transactions; a failed final RPC is rolled back and
the API attempts to mark the scan failed. If Supabase itself is unreachable,
that final failure update may also be unavailable. No worker, queue, or Redis is
introduced.

The additive migration `20260928120000_phase4f_scan_pipeline.sql` retains all 11
legacy `scan_checks` rows, seeds the 13 dotted canonical IDs idempotently, and
stores the explicit legacy-to-canonical relation on canonical rows. It adds
`scan_check_results`, changes scan lifecycle values to `pending`/`running`/
`completed`/`failed`, and restricts findings to the exact five scanner statuses.
Legacy `passed`/`failed` statuses are normalized to `pass`/`fail`; legacy
`passed` severity is normalized to `informational`. `findings.description` is
reused as the summary and `recommendation` as remediation; the migration adds
`why_it_matters`, `affected_url`, and structured metadata rather than duplicating
those established columns.

Score persistence uses the existing nullable `scans.score`, plus
`scoring_version`, controlled `score_confidence`, and `score_available`. The
versioned `score_details` JSONB stores coverage, category breakdown, weakest
categories, deductions, and unavailable reason codes; per-check score
explanations are stored alongside `scan_check_results`, avoiding a second copy
of the same list. `technologies.confidence_label` preserves the exact
low/medium/high scanner value while the existing numeric confidence column stays
backward-compatible (low `0.4`, medium `0.7`, high `0.9`); evidence signals and
metadata are structured JSONB, never response bodies.

Existing RLS ownership policies remain active for scans, findings, and
technologies. `scan_check_results` is RLS-enabled and readable only when its
parent scan is owned by `auth.uid()`; authenticated clients cannot write scan
results. `GET /api/scans/{scan_id}` first filters by both scan ID and verified
user ID before reading child rows, returning not-found for another user's scan.
The privileged client is created and used only by FastAPI; secret keys are not
returned or added to frontend environment configuration.

Scan creation is limited by a configurable in-memory per-user sliding window
(`SCAN_RATE_LIMIT_MAX_REQUESTS`, `SCAN_RATE_LIMIT_WINDOW_SECONDS`; defaults 5 per
60 seconds). This is process-local and not a global distributed quota; configure
edge/gateway rate limits before multi-worker or multi-replica deployment. CORS
uses exact `ALLOWED_ORIGINS` entries and rejects wildcard origins. Responses
strip target query strings, omit raw response bodies and cookie values, drop raw
server-header values, redact non-public IP/host URLs in evidence, and use
controlled error messages instead of exception or database details.

The migration was applied to hosted Supabase and the schema, grants, and RLS
were reviewed read-only. The repository pgTAP suites have not been run because
the local Supabase CLI/Docker/psql toolchain is unavailable. Global rate limiting
and deployment egress controls remain mandatory before public exposure.

### Phase 4G — authenticated scanner UI integration

The Next.js app exposes same-origin route handlers at `/api/scans` and
`/api/scans/{id}` as a backend-for-frontend boundary. Browser code talks only to
these routes. On each request, the server verifies the current Supabase session
claims, reads the matching access token from the existing Supabase SSR session,
and forwards it as a bearer token to FastAPI. The browser never receives the
scanner service URL or any backend secret. The BFF forwards only the URL on scan
creation, enforces same-origin POSTs and a bounded JSON body, rejects extra
fields, disables caching/redirect following, and replaces upstream error text
with a fixed safe message.

`GET /api/scans` is an authenticated, bounded history endpoint (1–100 rows per
page with an owner filter derived from the verified bearer token). It returns
safe scan summaries and completed-scan severity counts; the repository filters
the verified owner before looking up child findings. `GET /api/scans/{scan_id}`
continues to enforce scan ID plus owner before reading result rows. No RLS policy,
table grant, or service-role boundary was changed for the UI. Scan execution
remains synchronous; the UI does not poll or assume a background job.

The dashboard and history use actual owned scan records, with explicit loading,
empty, API-error, unavailable-score, and failed-scan states. Scan details render
score/category metadata, actionable findings, check results, and passive
technology indicators while omitting unsafe evidence keys and redacting address
and URL data again before display. The same-origin BFF/API is not an approval to
deploy publicly: keep scanner ingress private until outbound egress restrictions
and global/gateway rate limits are configured. A live scan was not run during
Phase 4G because no authenticated test-user token, backend credentials, or
explicitly authorized target was available.

### Phase 4H — private deployment safety hardening

#### Current code controls

The same-origin Next.js BFF continues to verify the Supabase session and forward
the user's access token server-side. It now also sends a distinct
`X-WebGuard-Scanner-Token`, read only from the Next.js server environment.
FastAPI requires this credential on all `/api/scans` routes before it verifies
the user token. It uses constant-time comparison, requires a configured value of
at least 32 characters, and fails closed with a generic response when it is
missing or invalid. The header is deliberately absent from FastAPI's CORS
allow-header list; browsers cannot obtain it from frontend code. This protects
the scanner from direct unauthenticated API calls but is **not** a replacement
for private network ingress or gateway controls.

FastAPI CORS still allows only configured exact origins; wildcard origins and
non-local HTTP origins are rejected. The browser calls only same-origin Next.js
routes, and scanner URL/token values remain server-only. `/health` returns only
`{"status":"ok"}` and does not report configuration, dependencies, or network
state. Rate-limit errors remain HTTP 429 with a fixed message and `Retry-After`;
the per-user in-memory limit remains five scan creations per 60 seconds by
default.

The synchronous scan path is bounded: the scanner overall timeout defaults to
30 seconds (configuration is capped at 120 seconds), the BFF aborts an upstream
request after 45 seconds, and the Next.js scanner route handlers declare a
60-second maximum execution duration. Keep the scanner timeout at its production
default unless load measurements justify a reviewed change; the deployed
function plan must honor the 60-second route budget. No worker or queue is used.

The Next.js response configuration sets `X-Content-Type-Options: nosniff` to
prevent MIME sniffing, `Referrer-Policy: strict-origin-when-cross-origin` to
avoid leaking full paths/queries cross-origin, and both CSP `frame-ancestors
'none'` and `X-Frame-Options: DENY` to prevent clickjacking. It intentionally
does not impose a broad script/style CSP, which needs a separate compatibility
review against Next.js runtime scripts and Supabase auth. It also disables the
default `X-Powered-By` header to avoid unnecessary framework fingerprinting.
Production builds add
`Strict-Transport-Security: max-age=31536000`; `includeSubDomains` and `preload`
are omitted until all subdomains are confirmed HTTPS-only. Production BFF
configuration requires the Render private `SCANNER_API_PRIVATE_HOSTPORT` on port
10000 and fails closed if it is missing/invalid; it does not fall back to
`SCANNER_API_URL` or a public FastAPI hostname. The private BFF hop uses HTTP,
because Render's published private-network docs do not establish transport
encryption. Public Supabase configuration rejects remote HTTP endpoints, and
signup will not fall back to an HTTP callback origin in production. Scanner TLS
certificate verification is not disabled or bypassed for HTTPS targets.

The application does not log request bodies, authorization headers, cookies,
Supabase tokens, scanner tokens, or scanner-resolved addresses. API errors use
fixed messages and do not return stack traces. Production ingress/access-log
configuration must also avoid capturing request/response headers, cookies,
bodies, authorization data, and query-bearing target URLs. Operational logs
should use status, route template, duration, and controlled error code only.

#### Phase 4I — Render private staging preparation

`render.yaml` defines two Render services in Singapore, the same region and
workspace required for Render private networking. Render's documented regions
do not include Mumbai, so Supabase connections cross regions over HTTPS:

- `webguard-staging-web`: public Next.js web service, `frontend/` root, Node
  22.22.0, `npm ci && npm run build`, and
  `NODE_ENV=production npm run start -- --hostname 0.0.0.0 --port $PORT`. `/login`
  is its HTTP health check. Render terminates public TLS and redirects public
  HTTP to HTTPS; the actual domain/certificate still require deployment
  verification.
- `webguard-staging-scanner`: `type: pserv` FastAPI service, `backend/` root,
  Python 3.12.11, `pip install -r requirements.txt`, and Uvicorn bound to
  `0.0.0.0:$PORT` with access logging disabled. Render private services support
  TCP health checks only, so Render probes the listening port. FastAPI's minimal
  `GET /health` remains available for a separate private application-level check.

The web service receives the scanner's Render-generated private `hostport` from
the private service through a Blueprint property reference. In production the
BFF accepts only a single-label host on port 10000 from
`SCANNER_API_PRIVATE_HOSTPORT`; it does not use a public scanner URL. Render's
private service type is not internet reachable, and services in the same
workspace and region can use the private network. This solves the **private
BFF-to-scanner ingress configuration requirement once deployed**. It does not
prove live private DNS/connectivity or establish a transport-encryption
guarantee. The Blueprint uses HTTP at the application layer, and Render's public
documentation describes traffic as not traversing the public internet but does
not claim service-to-service transport encryption.
Do not treat HTTP as TLS or remove either authentication factor. If policy
requires transport encryption, implement and test TLS with a trusted certificate
before treating this staging configuration as suitable.

Render references and networking model:
[render.com/docs/private-services](https://render.com/docs/private-services)
[render.com/docs/private-network](https://render.com/docs/private-network) and
[render.com/docs/blueprint-spec](https://render.com/docs/blueprint-spec).

The Blueprint requests operator-supplied Supabase and exact CORS values with
`sync: false`; generated scanner-token material is shared through a dedicated
Render environment group only with the two server services. Use a staging
Supabase project, not production credentials. Frontend `NEXT_PUBLIC_*` values
must be set before the build. The backend `ALLOWED_ORIGINS` value must be the
exact HTTPS origin of the deployed frontend (no wildcard or path).

This is a configuration manifest only. No Render workspace, service, DNS route,
secret value, deployment, or live connectivity is available or verified from this
checkout.

**Scanner network egress.** Render documents regional outbound IP ranges, which
are useful for destination-side allowlists, but does not document per-service
destination/port egress firewall rules. The current Render PaaS choice therefore
cannot satisfy this scanner's required egress policy by itself. Before running
the scanner, place it on a platform/network with enforceable outbound firewall
rules (or a network-enforced egress gateway) and default-deny outbound traffic.
The policy must:

- Permit scanner target TCP ports **80, 443, 8080, and 8443 only**. Do not add
  arbitrary target ports; these match `SCANNER_ALLOWED_PORTS` and Phase 4A URL
  validation.
- Permit DNS only to the designated resolver on UDP/TCP 53 and HTTPS to the
  configured Supabase project on TCP 443. Keep the resolver exception narrow;
  it must not provide general access to internal services.
- Deny loopback, private, link-local, shared/CGNAT, multicast, unspecified,
  documentation, benchmarking, reserved/special-use, cloud metadata, provider
  control-plane, and all other internal infrastructure destinations on both
  IPv4 and IPv6. Apply the provider's current metadata/internal CIDRs as well as
  the current IANA special-purpose address registries. Host/subnet firewalls do
  not necessarily filter loopback traffic, so enforce a process/container
  network policy for loopback and ensure no sensitive local admin/metadata
  service is listening in the scanner's network namespace. If IPv6 filtering
  cannot be established and tested, deny scanner IPv6 egress entirely rather
  than leave an unfiltered route.
- Ensure deny rules take precedence over broad public-target port allows;
  firewall/NAT alone is not proof of filtering. Application-level Phase 4A URL,
  DNS-answer, pinned-address, redirect, timeout, and port validation remains
  authoritative and must not be weakened.

Render outbound IP documentation:
[render.com/docs/outbound-ip-addresses](https://render.com/docs/outbound-ip-addresses).
Outbound IP ranges are not destination filtering.

**Edge and global rate limiting.** The Render Blueprint retains the existing
FastAPI in-process limit of five scan creations per user per 60 seconds. That
limit is not shared between workers/instances and does not rate-limit all public
traffic to the Next.js BFF. No gateway rule or global/shared counter is configured
by this Blueprint. Before production scanning, configure and verify an
appropriate route-level limit for `POST /api/scans` and a shared/global budget at
the selected edge or gateway. Do not treat generic DDoS protection or private
scanner ingress as an application rate limit, and do not remove the backend
per-user limit.

#### Production verification gate

Before public exposure, operators must complete and retain evidence for each:

1. **Ingress:** Verify the scanner is a Render Private Service with no public
   hostname/URL, and that both services are in the same Render workspace and
   region. From outside the private network, verify scanner access is unavailable;
   from the BFF runtime, verify the Blueprint-sourced private hostport resolves
   and is reachable. The configured hop is HTTP; do not record it as
   transport-encrypted. Confirm both missing and incorrect
   `X-WebGuard-Scanner-Token` values get a generic
   401 and a valid service token without a valid Supabase user token is still
   rejected. Confirm the service token is not present in browser bundles,
   responses, CORS allow-headers, traces, or logs.
2. **Egress:** Inspect the deployed firewall's effective rules and flow logs.
   From a controlled staging scanner, verify allowed public HTTP/HTTPS test
   endpoints on 80/443/8080/8443 work. Verify other ports fail. Verify loopback,
   private, link-local, IPv4/IPv6 special-use, metadata, and provider-internal
   destinations are denied by the network layer; use provider firewall test
   facilities or controlled canaries rather than probing production
   infrastructure. Confirm DNS works only through its approved resolver and
   Supabase persistence works over HTTPS/443. Re-test after firewall changes.
3. **Rate limiting:** Verify the five-per-minute authenticated backend limit,
   then verify a route-level gateway rule and shared/global behavior. No such
   gateway rule is supplied by this manifest. Regional or per-process counters
   alone do not satisfy a global quota.
4. **HTTPS/headers/logging/health:** Verify the public frontend and Supabase use
   HTTPS, inspect production response headers, and confirm TLS certificate
   verification for HTTPS scanner targets. Confirm FastAPI `/health` contains
   only `status`, the private service passes its TCP check, and logs contain no
   credentials, bodies, cookies, bearer tokens, or unnecessary internal IPs.
   Render's published docs do not establish encryption for private-network
   service traffic; this manifest's BFF hop is HTTP.
5. **Environment/API boundary:** Verify the three `NEXT_PUBLIC_*` values are
   the only client-exposed configuration. Confirm the secret key, scanner token,
   `SCANNER_API_PRIVATE_HOSTPORT`, and backend CORS allowlist are set only in
   server environments. Verify a browser can reach only same-origin Next.js
   scanner routes and the FastAPI service is inaccessible from the public
   internet.
6. **Synchronous duration:** Confirm the deployed Next.js runtime honors the
   route's 60-second maximum, the BFF's 45-second timeout, and FastAPI's bounded
   scanner deadline. Render's public documentation reviewed for this phase does
   not specify a conflicting HTTP request-duration cap; verify actual staging
   behavior with a controlled slow authorized target. Do not raise application
   limits to hide a platform timeout.

Until private ingress, enforceable egress rules, and edge/global rate limits are
configured and verified, the scanner service must remain unavailable to public
traffic. Code-level service authentication is not a deployment approval.

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
- status (`pending`, `running`, `completed`, or `failed`)
- score (nullable integer, 0–100)
- score_available
- scoring_version
- score_confidence
- score_details (JSONB coverage/category roll-up)
- started_at
- completed_at
- duration_ms
- error_code (controlled failure code)
- error_message
- created_at

### findings
- id
- scan_id
- check_id
- title
- severity
- status
- description (scanner summary)
- why_it_matters
- evidence
- recommendation (remediation)
- affected_url (query stripped)
- metadata
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
- is_canonical
- legacy_check_id (explicit mapping on canonical rows; legacy rows retained)

### scan_check_results
- scan_id
- check_id
- status / severity
- scoring_relevant
- scoring_version / check_version
- reason / evidence
- score_explanation (per-check JSONB)

### technologies
- id
- scan_id
- name
- category
- confidence (backward-compatible numeric projection)
- confidence_label (`low`, `medium`, `high`)
- evidence (JSONB signal names)
- metadata

### scan_ai_summaries and finding_ai_explanations (Phase 5 migration)
- Store only validated AI-generated text, provider/model label, generation time,
  prompt version, and a hash of the sanitized deterministic input.
- A summary is unique per scan; an explanation is unique per finding and a
  composite foreign key ensures the finding belongs to the referenced scan.
- RLS allows authenticated reads only when the linked scan belongs to `auth.uid()`;
  authenticated clients cannot insert/update/delete. The backend service role is
  the only persistence writer.

Authenticated clients can read their own scans and delete their own scans.
FastAPI validates each bearer token by asking Supabase Auth to load the user,
then derives `user_id` from that verified user record. FastAPI uses the
server-only Supabase secret key through the pinned `supabase-py` async client for
scan/result writes. Never trust a caller-supplied user ID. Profiles permit
owner-only read/insert/update. The global `scan_checks` catalog is read-only to
authenticated users. Anonymous Data API access is not granted.

RLS is enabled on all six core public tables. The Phase 5 migration adds RLS to
both AI tables (eight tables total after it is applied). Explicit table grants
complement the row policies: `anon` receives no table privileges; `authenticated` receives only
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

The authenticated Phase 4G UI routes are `/dashboard`, `/scans`, `/scans/[id]`,
and `/settings`. Protected views require a verified user and render real owner-
filtered scan data from the same-origin BFF. `/login`, `/signup`, and
`/auth/confirm` are public routes. The UI does not fabricate scan outcomes; a
live authenticated scan remains unverified without staging credentials, a test
user, and an explicitly authorized target.

### Environment variable boundaries

- Public/browser-visible frontend values: `NEXT_PUBLIC_SUPABASE_URL`,
  `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY`, and `NEXT_PUBLIC_SITE_URL`. The
  Supabase URL and publishable key are non-secret; RLS and authentication enforce
  data access. Production URLs must use HTTPS.
- Next.js server-only values: local development uses `SCANNER_API_URL`; Render
  production uses `SCANNER_API_PRIVATE_HOSTPORT` plus `SCANNER_API_TOKEN`. These
  are read only by the BFF and are never prefixed `NEXT_PUBLIC_`, serialized into
  HTML, or returned to the browser. Production fails closed if the private
  hostport is missing or malformed; it does not fall back to a public scanner URL.
- FastAPI optional AI values: `AI_PROVIDER`, `AI_API_KEY`, `AI_MODEL`, and
  `AI_BASE_URL`, plus `AI_RATE_LIMIT_MAX_REQUESTS` and
  `AI_RATE_LIMIT_WINDOW_SECONDS`. These are backend-only. OpenAI and OpenRouter
  have known HTTPS defaults; `openai-compatible` requires a configured base URL.
  Plain HTTP is accepted only for local loopback development. Never pass a
  provider key through the frontend or a user request.
- FastAPI server-only values: `SUPABASE_URL`, `SUPABASE_PUBLISHABLE_KEY`,
  `SUPABASE_SECRET_KEY`, `SCANNER_API_TOKEN`, and `ALLOWED_ORIGINS`, plus scanner
  limits. `SUPABASE_SECRET_KEY` is privileged/RLS-bypassing. The random
  `SCANNER_API_TOKEN` (minimum 32 characters) is shared only between the Next.js
  server and FastAPI. The BFF also forwards the current user's Supabase access
  token; FastAPI independently verifies it and derives the owner. `ALLOWED_ORIGINS`
  is an exact-origin backend setting, never browser configuration. Supabase,
  public frontend, and external HTTPS target connections use HTTPS. The Render
  private BFF-to-FastAPI connection is HTTP on the private network, with no
  transport-encryption claim.
- Use `frontend/.env.example` and `backend/.env.example` separately. Root
  `.env.example` is a convenience reference, not an environment file to load.
  Generate a new random service token for every deployment; do not use or commit
  the blank/example values.

The local CLI config disables automatic exposure of new tables. Every required
Data API privilege is explicitly granted in the migration after RLS is enabled.

## 6. Security Boundaries

### Browser → Next.js
Use authenticated sessions and server-side validation.

### Next.js → FastAPI
Use Render's private service path plus both the server-only
`X-WebGuard-Scanner-Token` and the user's verified Supabase bearer token. The
Render staging path is HTTP and is not documented as transport-encrypted. Never
trust user-provided user IDs. The service token is not permitted by browser CORS.

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
controls. Phase 4F now composes those controls with checks/scoring behind the
authenticated scan routes; outbound firewall/egress restrictions remain a
deployment responsibility and are not replaced by application-level SSRF checks.

## 7. API Design

### POST /api/scans
Create and synchronously complete a scan (201 on completion; controlled failure
response otherwise). Requires the BFF-only `X-WebGuard-Scanner-Token` and
`Authorization: Bearer <Supabase access token>`; both are server-to-server
headers, not browser credentials.

Input:
```json
{
  "url": "https://example.com"
}
```

### GET /api/scans/{scan_id}
Get a scan's status and result only when it belongs to the verified caller; other
users receive the same not-found response as unknown IDs.

`GET /api/scans` returns authenticated owner-filtered history. AI generation is
available only on explicit POST requests after ownership/completion checks:

- `POST /api/scans/{scan_id}/ai/summary` with `{}` or `{"regenerate": true}`
- `POST /api/scans/{scan_id}/findings/{finding_id}/ai/explanation` with the same body

Both routes require the BFF-only service token and verified user's bearer token.
They return strict structured text, cache it in the separate AI tables, and never
accept target URLs or arbitrary prompt text. Rate-limit errors include
`Retry-After`. Scan result and score fields are not modified by either route.

The request model accepts only a URL; it does not accept caller headers, methods,
proxy/DNS settings, cookies, credentials, or a user ID. Validation errors do not
echo the request body.

## 8. Scan Lifecycle

```text
PENDING
   |
   v
RUNNING
   |
   +----> FAILED
   |
   v
COMPLETED
```

## 9. Scoring

The Phase 4D scoring design is documented in [`scoring.md`](scoring.md). It
selects a deterministic, category-weighted, check-aware deduction methodology
for a 0–100 WebGuard security configuration score, with per-check point caps,
status/evidence rules, coverage gates, separate complete/partial/limited
confidence, and `scoring_version = "1.0"`. Severity is not converted to points.

Phase 4E implements the formula in `backend/app/scanner/scoring.py` as a pure
analysis of scanner findings. Phase 4F calls that engine without duplicating the
formula and persists its score, availability, confidence, coverage/category
details, and per-check explanations. The UI must state that the score is a
WebGuard security configuration score and not a guarantee that a website is
secure. The Phase 4F schema migration must be applied before the API can persist
results to the hosted project.

## 10. Error Handling

Return stable error structures.

Example:
```json
{
  "error": {
    "code": "invalid_target",
    "message": "The target URL is invalid or not allowed."
  }
}
```

Do not expose internal stack traces to users.
Target validation, blocked destinations, network failures, timeouts, scanner
errors, and persistence failures have controlled error codes/messages. Persisted
error text is never reflected directly by the read API.

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
- AI ownership, validation, caching, rate-limit, prompt-injection, redaction, and
  no-network-on-report-load tests

### Integration
- authenticated scan creation
- completed scan retrieval
- ownership isolation for scan retrieval

## 12. Deployment Architecture

The staging target is Render Next.js web service → Render FastAPI Private
Service → Supabase and authorized public targets. The exact service definitions
are in `render.yaml`, and deployment/verification gates are recorded in [Phase
4I](#phase-4i--render-private-staging-preparation). Render private networking
provides private ingress when both services are in the same region/workspace; it
does not provide destination-level scanner egress filtering. The BFF hop is HTTP
in this manifest; Render's documentation does not claim this private traffic is
transport-encrypted. No service deployment, live connectivity, egress firewall,
production TLS, or shared/global rate limit is verified. Keep the scanner in
private staging and do not authorize unrestricted production scanning until the
remaining gates pass.
