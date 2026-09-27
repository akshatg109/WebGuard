# WebGuard — Product Requirements Document

## 1. Product Overview

WebGuard is a web security analysis platform that lets authorized users scan a website and receive a clear, actionable assessment of common web security configuration issues.

The product should feel like a real security SaaS application rather than a college demo.

## 2. Problem

Website owners and developers often know that security matters but do not have an easy way to understand basic security configuration problems.

WebGuard converts technical checks into:
- a security score
- prioritized findings
- explanations
- remediation guidance
- historical scan data
- downloadable reports

## 3. Target Users

### Primary
- Student developers
- Freelance developers
- Startup developers
- Website owners
- Small engineering teams

### Secondary
- Security learners
- DevOps learners
- Developers reviewing their own deployments

## 4. Core User Flow

1. User signs up or logs in.
2. User enters an authorized website URL.
3. WebGuard validates the target.
4. User starts a scan.
5. Backend performs safe security/configuration checks.
6. Results are stored.
7. User sees a security score and findings.
8. User opens individual findings for explanations.
9. User can compare historical scans.
10. User can export a report.

## 5. MVP Features

### Authentication
- Email/password authentication
- Protected dashboard
- Logout
- User profile

### Website scanning
- URL validation
- HTTP/HTTPS reachability
- Redirect analysis
- Security header analysis
- Cookie security attributes where observable
- TLS/HTTPS configuration checks
- Basic technology detection
- Response metadata
- Scan timing and status

### Security checks
Initial checks should include safe checks for:
- HTTPS usage
- HTTP-to-HTTPS redirect behavior
- HSTS
- Content-Security-Policy
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy
- frame-ancestors / X-Frame-Options
- secure cookie attributes when observable
- server information exposure
- mixed-content indicators where safely detectable

### Results
- Overall score
- Severity breakdown
- Passed checks
- Findings
- Recommendation for each finding
- Scan timestamp
- Target URL

### Scan history
- Previous scans
- Scan status
- Score history
- Target history
- Open previous report

### MVP scope clarification

PDF export is explicitly out of scope for the MVP. The MVP supports viewing scan
results and history in the application; downloadable PDF reports are a later
feature. MVP scans run synchronously through the scanning API.

## 6. Post-MVP Features

- PDF reports
- Scheduled scans
- Email notifications
- Technology fingerprinting
- More passive security checks
- Team workspaces
- Role-based access
- Public/shareable reports
- AI explanations
- AI-generated remediation summaries
- API access
- Usage limits and subscription tiers

## 7. Non-Goals

WebGuard will not initially:
- exploit vulnerabilities
- brute-force credentials
- perform password attacks
- deploy malware
- provide persistence
- bypass authentication
- conduct destructive testing
- run arbitrary commands against targets
- act as an offensive exploitation framework

## 8. Security and Safety Requirements

Because the scanner accepts user-controlled URLs, SSRF protection is a critical requirement.

URL validation, SSRF protection, timeouts, redirect limits, response-size limits,
and rate limiting are foundational MVP requirements; they are not deferred to
production hardening.

The backend must:
- validate URL schemes
- reject unsafe schemes
- restrict or carefully handle private/internal IP destinations
- prevent access to cloud metadata endpoints
- enforce connection and response timeouts
- limit response sizes
- limit redirects
- rate-limit scan requests
- avoid forwarding arbitrary user headers
- avoid storing sensitive response data unnecessarily

## 9. Product Quality Requirements

The application should:
- work on desktop and mobile
- provide clear loading states
- provide useful empty states
- provide understandable errors
- be accessible
- use consistent severity terminology
- avoid exposing implementation details unnecessarily

## 10. Success Criteria

MVP is successful when an authenticated user can:
1. Enter a valid website they are authorized to test.
2. Start a scan.
3. Receive a completed result.
4. Understand the score.
5. Inspect findings.
6. Read remediation guidance.
7. View the scan later in history.

## 11. Portfolio Goals

The project should demonstrate:
- production-style full-stack architecture
- clean TypeScript
- modern React/Next.js patterns
- API design
- database design
- authentication
- defensive security engineering
- deployment
- polished UI/UX
- maintainable code
