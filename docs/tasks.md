# WebGuard — Tasks & Progress

Legend:
- [ ] Not started
- [~] In progress
- [x] Completed
- [!] Blocked

## Phase 0 — Planning

- [x] Define product concept
- [x] Define documentation structure
- [x] Create PRD
- [x] Create architecture
- [x] Create UI/UX direction
- [x] Create task tracker
- [x] Create project memory
- [x] Create OpenCode instructions

## Phase 1 — Repository Foundation

- [x] Initialize/confirm Git repository at `/home/akshat/projects/WebGuard`
- [x] Initialize Next.js frontend in `frontend/`
- [x] Configure TypeScript strict mode
- [x] Configure Tailwind CSS
- [x] Install and configure shadcn/ui
- [x] Initialize FastAPI backend in `backend/`
- [x] Create environment variable templates
- [x] Create README
- [x] Establish frontend/backend folder structure

## Phase 2 — Supabase

- [x] Create dedicated WebGuard Supabase project (Mumbai, `ap-south-1`)
- [~] Configure authentication (SSR clients and actions prepared; hosted email/redirect settings pending)
- [x] Create database schema migration (written and applied to hosted project; pgTAP execution pending)
- [~] Configure row-level security and explicit Data API grants (migration applied and RLS enabled; pgTAP/grant verification pending)
- [x] Create profiles table (present in hosted schema)
- [x] Create scans table (present in hosted schema)
- [x] Create findings table (present in hosted schema)
- [x] Create technologies table (present in hosted schema)
- [x] Create scan_checks catalog table (present in hosted schema)
- [x] Add database indexes to the migration
- [x] Add database ownership/RLS pgTAP test suite
- [x] Prepare SSR clients, verified-claims route protection, and auth server actions
- [x] Prepare FastAPI server-only Supabase settings and async client factory

## Phase 3 — Premium UI Foundation

- [x] Build application shell
- [x] Build sidebar/navigation
- [x] Build responsive header and mobile navigation sheet
- [x] Configure dark design tokens and severity semantic colors
- [x] Build reusable card, metric, page-header, status, and finding components
- [x] Build severity badges
- [x] Build loading skeletons
- [x] Build empty states
- [x] Build route error states
- [x] Build accessible Login and Signup pages with validation and async feedback
- [x] Build email confirmation callback and auth recovery states
- [x] Protect dashboard, scans, scan reports, and settings with verified Supabase claims
- [x] Build Dashboard with explicit no-data placeholders and a non-scanning New Scan dialog
- [x] Build responsive Scans table with sort, search, status filter, pagination, and empty state
- [x] Build scan report layout with findings/check/technology/remediation placeholders
- [x] Build modular account and security Settings page with sign out
- [x] Add clearly separated empty preview data; no mock site results or scores
- [x] Verify desktop/mobile auth layout and unauthenticated protected-route redirects

## Phase 4 — Authentication

Authentication screens/session work below were implemented within Phase 3 because
they were explicitly included in its approved scope. Phase 4 remains unopened;
these tracker items are left untouched until that phase is approved.

- [ ] Login
- [ ] Signup
- [ ] Logout
- [ ] Protected routes
- [ ] Session handling
- [ ] Profile page

## Phase 4A — Secure Scanner Foundation

- [x] Establish isolated `backend/app/scanner/` architecture and internal scan context
- [x] Implement strict HTTP/HTTPS URL parsing, IDN normalization, port policy, and canonicalization
- [x] Reject credentials, local names, ambiguous IP forms, and unsafe IPv4/IPv6 literals
- [x] Resolve hostnames, validate every answer, and reject mixed unsafe DNS sets
- [x] Pin vetted DNS answers into an aiohttp resolver to prevent re-resolution/rebinding
- [x] Enforce manual redirects, destination validation, hop limits, and loop detection
- [x] Restrict requests to bounded GET/HEAD with safe headers, no cookies, and no environment proxies
- [x] Configure DNS/connect/read/write/overall deadlines, concurrency, and response byte limits
- [x] Add safe structured scanner errors and partial response-head context for oversize bodies
- [x] Add deterministic URL, DNS/IP, redirect, transport, response-limit, and error tests
- [!] Add OS/deployment egress firewall rules for private and metadata destinations (requires an egress-filtering deployment platform)

Phase 4A intentionally does not implement any individual security checks or scoring.
There is no public scan endpoint and no scanner persistence in this subphase.

## Phase 4B — Core Website Security Checks

- [x] Add typed finding severities, categories, statuses, observed summaries, why-it-matters text, evidence, remediation, and safe affected URLs
- [x] Add deterministic check interface and explicit registry with isolated check errors
- [x] Add transport HTTPS, final-scheme, and HTTP-to-HTTPS redirect checks
- [x] Add HSTS directive parsing and evidence
- [x] Add CSP presence/parseability, unsafe-inline/eval, and broad-source observations
- [x] Add X-Content-Type-Options, Referrer-Policy, and Permissions-Policy checks
- [x] Add X-Frame-Options/CSP frame-ancestors protection analysis
- [x] Add Server/X-Powered-By disclosure check
- [x] Add deterministic check tests, including duplicate/case-insensitive headers
- [x] Keep scoring, persistence, API routes, and frontend integration out of scope

## Phase 4C — Extended Security Checks

- [x] Normalize captured Set-Cookie attributes while discarding raw cookie values
- [x] Aggregate cookie Secure/HttpOnly/SameSite/scope/Max-Age/Expires observations
- [x] Apply Secure checks only to HTTPS responses and report SameSite=None without Secure
- [x] Add bounded passive mixed-content detection for captured HTTPS HTML/XHTML
- [x] Distinguish active HTTP resource references from passive image/media references
- [x] Add conservative passive technology signals and controlled confidence levels
- [x] Ensure cookie values, full resource URLs, and arbitrary HTML snippets are not returned
- [x] Verify check code performs no requests, crawling, or JavaScript execution
- [x] Add deterministic Phase 4C tests; preserve all Phase 4A/4B tests

No subresource fetching, crawling, persistence, score, or public scan API was added.

## Phase 4D — Security Scoring Design

- [x] Inventory Phase 4A/4B/4C scanner checks and observed status/evidence behavior
- [x] Inspect `scans`, `findings`, and `scan_checks` in the migration and live Supabase schema
- [x] Compare scoring approaches and select one documented deterministic methodology
- [x] Define category/check allocations, outcome deductions, N/A/errors, partial evidence, and confidence
- [x] Define score output explanation, score/check versioning, and future persistence needs
- [x] Add at least three hypothetical worked examples in `docs/scoring.md`
- [x] Verify documentation-only changes without changing scanner behavior

Phase 4D is design-only and complete. No scoring calculation code, production
weights, database changes, public endpoint, or frontend integration was added.
The approved design is implemented separately in Phase 4E below.

## Phase 4E — Scoring Engine v1.0 and Check Catalog Reconciliation

- [x] Re-read project requirements, scoring design, scanner findings/checks, and local/live schema
- [x] Reconcile all 13 canonical scanner IDs against 11 legacy catalog IDs without renaming scanner IDs
- [x] Keep technology/exposure informational and transport redirect/final-scheme diagnostic-only
- [x] Implement a pure, deterministic scoring engine with one `SCORING_VERSION` constant
- [x] Apply documented category budgets, check-specific deductions, aggregation caps, and N/A/error semantics
- [x] Enforce applicable-points, point-coverage, and check-count coverage gates with structured unavailable reasons
- [x] Return confidence, category breakdown, and deterministic check-level explanation metadata
- [x] Add exact worked-example, status, coverage, duplicate, informational, invariant, and no-network tests
- [x] Preserve Phase 4A–4C scanner behavior; add no persistence, route, frontend, AI, or PDF feature
- [x] Document required future catalog/status/score-metadata migration without applying it

Phase 4E is complete. Its score methodology, IDs, and pure implementation are
preserved by Phase 4F.

## Phase 4F — Authenticated Scan API and Supabase Persistence

- [x] Re-read requirements, scanner phases 4A–4C, scoring design/engine, and live schema/RLS
- [x] Add an additive migration preserving 11 legacy IDs and seeding all 13 canonical IDs with explicit mappings
- [x] Add JSONB scoring persistence and controlled finding/scan status constraints
- [x] Add ownership-protected `scan_check_results` table and restricted atomic completion RPC (service-role grant; public/authenticated roles revoked)
- [x] Verify Supabase access tokens with Supabase Auth and derive owner UUID from verified user
- [x] Add authenticated `POST /api/scans` and owner-filtered `GET /api/scans/{scan_id}`
- [x] Add configurable per-user in-process scan rate limiting and exact-origin CORS
- [x] Connect safe URL validation → `ScannerService` → checks → score → persistence synchronously
- [x] Persist findings, passive technologies, canonical check results, and score metadata without raw bodies/cookie values
- [x] Add controlled failure responses, safe failed-scan state, response scrubbing, and request validation
- [x] Add deterministic auth/API/pipeline/persistence tests and pgTAP catalog/status/RLS tests
- [x] Keep the frontend unchanged; add no AI, PDF, Redis, queue, or worker
- [x] Review/apply `20260928120000_phase4f_scan_pipeline.sql` to hosted Supabase and verify hosted schema/grants/RLS read-only
- [!] Run pgTAP catalog/status/RLS suites; local Supabase CLI, Docker, and `psql` are unavailable here
- [!] Configure deployment-level outbound egress restrictions and global/edge rate limits before public deployment

Phase 4F implementation is complete locally and its migration is applied to the
hosted project. Do not expose the scanner publicly until outbound egress and
global/gateway rate-limit controls are configured.

## Phase 4G — Authenticated Scanner Frontend Integration

- [x] Add a typed scanner API client that calls only the same-origin Next.js BFF
- [x] Forward the existing verified Supabase access token server-side; keep `SCANNER_API_URL` server-only
- [x] Enforce URL-only scan creation, accessible validation, safe API errors, and disabled in-flight submission
- [x] Add an authenticated, owner-filtered, bounded `GET /api/scans` summary endpoint without a migration
- [x] Connect dashboard score/availability/confidence, latest severity summary, total scans, and recent history
- [x] Connect scan history search/filter/sort/pagination and detail links to live owned scan data
- [x] Render real scan details, category scoring, findings, check results, technologies, and safe failed/incomplete states
- [x] Preserve the existing visual system and add no AI, PDF, Redis, workers, or public deployment
- [x] Run frontend lint/typecheck/build and the complete backend test suite (190 tests)
- [x] Browser-smoke `/login`, `/signup`, and unauthenticated redirects for protected routes; verify unauthenticated scanner API returns 401
- [!] Complete an authenticated browser scan and protected-page rendering: no valid test-user session/backend credentials/explicitly authorized target are available
- [!] Run automated frontend component tests: this frontend has no configured test runner; no new dependency was added

Phase 4G is complete within the available environment. No live scan was
fabricated or sent.

## Phase 4H — Private Deployment Safety Hardening

- [x] Review Phase 4A SSRF validation, exact target ports, bounded synchronous duration, health, CORS, rate-limit responses, environment boundaries, and logging
- [x] Add a separate server-only BFF-to-FastAPI token while retaining verified Supabase user authentication
- [x] Fail closed when the scanner service token is missing/weak; keep it out of browser CORS
- [x] Require HTTPS for production Supabase URLs and signup callbacks; Phase 4I constrains the private BFF hop to the Render hostport
- [x] Add minimal production security headers without a broad CSP that could break Next.js/Supabase auth
- [x] Split environment references into frontend and backend templates with public/server-only comments
- [x] Document private ingress options, Render egress limitations, edge/shared rate-limit gaps, required network policy, and exact verification procedure
- [!] Deploy and verify private service ingress from the BFF to FastAPI; Phase 4I prepares the Render hostport configuration, but no services are deployed here
- [!] Configure and verify network-level IPv4/IPv6 egress deny rules and target-port restrictions; current Render PaaS configuration has no per-service egress firewall in this repository
- [!] Configure and verify route-level/gateway rate limits; no shared global counter is configured
- [!] Keep scanner ingress unavailable to public traffic until private ingress, egress filtering, and the required gateway limits are verified

Phase 4H code/documentation work is complete. Deployment controls are not
configured or verified in this local checkout; the scanner remains blocked from
public exposure until all `[!]` deployment gates above are cleared.

## Phase 4I — Render Private Staging Preparation

- [x] Add a Render Blueprint with a public Next.js web service and a FastAPI `pserv` in the same region
- [x] Configure the Next.js production start/build commands, HTTPS origin inputs, health path, and Node runtime
- [x] Configure FastAPI production start command, Python runtime, private TCP health probe, exact CORS input, and scanner limits
- [x] Wire BFF routing from the scanner Private Service's Render `hostport` property; production fails closed instead of using a public scanner URL
- [x] Keep both the verified Supabase user token and server-only scanner token required
- [x] Keep Supabase secret and scanner token server-side; share only the generated scanner token between the two server services
- [x] Review code logging and disable Uvicorn access logs; document that Render provider-log redaction is not verified
- [x] Document private-network HTTP and the absence of a Render transport-encryption claim
- [x] Document that Render private networking solves private ingress but does not provide destination-level scanner egress filtering
- [x] Update README, architecture, task, and memory documentation for the Render staging target
- [!] Deploy the Blueprint and enter staging secrets; no Render workspace/service credentials are available here
- [!] Verify private BFF-to-FastAPI DNS/connectivity and confirm FastAPI has no public endpoint
- [!] Run an external-target scan; no authorized target or valid staging user session was provided
- [!] Configure/verify scanner egress firewall and IPv4/IPv6 destination restrictions
- [!] Configure/verify route-level and global/shared rate limits
- [!] Verify production HTTPS/TLS and provider log redaction

Phase 4I configuration preparation is complete, but infrastructure remains
unverified. Keep WebGuard in private staging and do not enable unrestricted
production scanning.

## Phase 5 — Scanner MVP Integration and Scoring

- [x] URL parser
- [x] URL validation (Phase 4A)
- [x] SSRF protections (Phase 4A)
- [x] HTTP request engine (Phase 4A)
- [x] Timeout handling (Phase 4A)
- [x] Redirect handling (Phase 4A)
- [x] Response size limits (Phase 4A)
- [x] HTTPS check (Phase 4B)
- [x] HSTS check (Phase 4B)
- [x] CSP check (Phase 4B)
- [x] X-Content-Type-Options check (Phase 4B)
- [x] Referrer-Policy check (Phase 4B)
- [x] Permissions-Policy check (Phase 4B)
- [x] X-Frame-Options/frame-ancestors check (Phase 4B)
- [x] Cookie attribute checks (Phase 4C)
- [x] Server header exposure check (Phase 4B)
- [x] Basic passive technology detection (Phase 4C)
- [x] Passive mixed-content reference detection (Phase 4C)
- [x] Implement synchronous scan execution (no Redis or background worker) — Phase 4F
- [x] Complete scoring design (deterministic formula and documented weights) before final scoring implementation — Phase 4D; see `docs/scoring.md`
- [x] Implement pure scoring methodology and canonical catalog — Phase 4E
- [x] Connect score engine to authenticated scan pipeline and persistence — Phase 4F

## Phase 6 — Scan API

- [x] POST scan endpoint (authenticated, synchronous)
- [x] GET scan endpoint (owner-filtered single scan)
- [x] GET scan history endpoint (bounded, owner-filtered summaries)
- [x] Scan status lifecycle (pending/running/completed/failed)
- [ ] Findings endpoint
- [x] Database persistence
- [x] Stable API error format
- [x] Safe diagnostics for scan-history persistence failures
- [x] Rate limiting (process-local MVP; global deployment limit remains)
- [ ] Request logging without secrets

## Phase 7 — Results Dashboard

- [x] Scan form
- [x] Synchronous scan submission/loading and actual pending/running/completed/failed states
- [x] Security score with availability, confidence, and scoring version
- [x] Latest-scan severity breakdown
- [x] Finding cards and safe observed evidence
- [x] Finding explanations/details
- [x] Passed, failed, warning, not-applicable, and error check results
- [x] Passive technology list
- [x] Finding remediation guidance

## Phase 8 — Scan History

- [x] Authenticated scan history page
- [x] Search/status filter
- [x] Sort and local pagination
- [x] Owner-filtered previous scan details
- [ ] Score history chart
- [ ] Delete scan functionality

## Phase 9 — Reports

- [ ] Report layout
- [ ] PDF generation
- [ ] Report download
- [ ] Report metadata
- [ ] Print-friendly results

Note: PDF export is explicitly out of scope for MVP and remains a later-phase feature.

## Phase 10 — AI Features

- [x] Optional OpenAI-compatible provider adapter; credentials remain FastAPI-only and AI is disabled when unconfigured
- [x] Explicit user-triggered explanation for an owned finding in a completed scan
- [x] Explicit user-triggered summary grounded in existing findings (not a score or security verdict)
- [ ] Separate executive-summary format
- [x] Strict structured output validation and deterministic evidence attribution
- [x] Per-user generation limit, retry guidance, and cache reuse/regeneration behavior
- [x] Prompt-injection boundary, input redaction, provider failure, malformed-output, and no-report-load-call tests
- [x] Responsive accessible UI for generate, loading, unavailable, error, retry, saved, and regenerate states
- [x] Additive AI persistence migration with owner-based RLS and pgTAP assertions
- [x] Apply Phase 5 migration to hosted WebGuard; verify schema and RLS read-only
- [ ] Execute pgTAP against local/staging Supabase

## Phase 11 — Production Hardening

- [ ] Automated tests
- [ ] SSRF test suite
- [ ] Security check test suite
- [ ] API integration tests
- [ ] Frontend E2E test
- [ ] Error monitoring
- [ ] Additional production rate-limit and resource-limit hardening beyond the foundational MVP controls
- [x] Dependency audit (`npm audit` and `pip-audit`; no known vulnerabilities reported)
- [ ] Production environment configuration

## Phase 12 — Deployment

- [ ] Deploy frontend
- [ ] Deploy backend
- [ ] Configure Supabase production
- [ ] Configure environment variables
- [ ] Configure CORS
- [ ] Configure domain
- [ ] Verify production scan
- [ ] Verify authentication
- [ ] Verify reports

## Phase 13 — Portfolio Polish

- [ ] Write high-quality README
- [ ] Add architecture diagram
- [ ] Add screenshots
- [ ] Add demo credentials if appropriate
- [ ] Add live demo
- [ ] Add project description to resume
- [ ] Add project to LinkedIn
- [ ] Record short demo video

## Current Focus

The local scan-history GET now returns 200 with Uvicorn loading `backend/.env`.
Scan creation POSTs still return 503; the API now logs redacted PostgREST
diagnostics for persistence stages so the failing stage can be identified on
the next authorized scan attempt. Supabase schema, service-role insert grant,
and status constraint were verified read-only; no scan data was created or read.

Phase 4I private Render staging preparation is complete: `render.yaml` defines a
Render Next.js web service and a FastAPI Private Service, and production BFF
routing requires the generated private hostport. This configuration is not
deployed. Private connectivity, scanner egress filtering, IPv4/IPv6 restrictions,
shared/global rate limits, production TLS verification, and provider log
redaction remain unverified. Hosted Phase 4F and Phase 5 migrations are applied;
read-only hosted checks confirmed the AI persistence schema, composite FK and
supporting index, ownership RLS, anonymous denial, 13 canonical IDs, scoring
artifacts, and migration history. Cross-user restrictions were verified from
policy definitions, not impersonated live sessions. The pgTAP suites remain
unexecuted because local database tooling is unavailable. No live provider
credentials or model requests were used. PDF, workers, public FastAPI ingress,
and unrestricted production scanning remain out of scope.

## Definition of Done

A task is complete when the implementation works, has appropriate validation/error handling, and does not break existing functionality.
