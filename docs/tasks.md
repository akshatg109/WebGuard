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
- [~] Create database schema migration (written; hosted application pending)
- [~] Configure row-level security and explicit Data API grants (written; pgTAP execution and hosted application pending)
- [~] Create profiles table
- [~] Create scans table
- [~] Create findings table
- [~] Create technologies table
- [~] Create scan_checks catalog table
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
- [ ] Add OS/deployment egress firewall rules for private and metadata destinations

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
- [ ] Implement synchronous scan execution (no Redis or background worker)
- [ ] Complete scoring design (deterministic formula and documented weights) before final scoring implementation

## Phase 6 — Scan API

- [ ] POST scan endpoint
- [ ] GET scan endpoint
- [ ] Scan status
- [ ] Findings endpoint
- [ ] Database persistence
- [ ] Stable API error format
- [ ] Rate limiting
- [ ] Request logging without secrets

## Phase 7 — Results Dashboard

- [ ] Scan form
- [ ] Scan progress state
- [ ] Security score
- [ ] Severity breakdown
- [ ] Finding cards
- [ ] Finding details
- [ ] Passed checks
- [ ] Technology list
- [ ] Recommendations

## Phase 8 — Scan History

- [ ] Scan history page
- [ ] Search/filter
- [ ] Sort
- [ ] Previous scan details
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

- [ ] AI provider integration
- [ ] Explain finding
- [ ] Generate remediation summary
- [ ] Generate executive summary
- [ ] AI output validation
- [ ] Usage limits

## Phase 11 — Production Hardening

- [ ] Automated tests
- [ ] SSRF test suite
- [ ] Security check test suite
- [ ] API integration tests
- [ ] Frontend E2E test
- [ ] Error monitoring
- [ ] Additional production rate-limit and resource-limit hardening beyond the foundational MVP controls
- [ ] Dependency audit
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

Phase 4C — Extended Security Checks (implementation complete; awaiting review)

Phase 2 — Supabase hosted migration application and pgTAP execution remain
pending database credentials and Docker access. Phase 4D and later work are not
started. The scanner still has no public endpoint, persistence, frontend
integration, or overall score. Complete and document deterministic scoring
design in its approved phase before score implementation.

## Definition of Done

A task is complete when the implementation works, has appropriate validation/error handling, and does not break existing functionality.
