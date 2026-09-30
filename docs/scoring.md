# WebGuard Security Configuration Score — Design

**Status:** The methodology was approved in Phase 4D, implemented as a pure engine
in Phase 4E, and connected to the authenticated synchronous persistence pipeline
in Phase 4F. Phase 4G consumes its score availability, confidence, category
breakdown, and per-check explanations in the authenticated UI. This document is
the rule of record for the implementation.

## Purpose and scope

The number is a **WebGuard security configuration score**. It summarizes the
specific HTTP/TLS, response-header, observable-cookie, and captured-HTML
configuration evidence available to this scanner. It does not measure complete
application security, prove the absence of vulnerabilities, describe
penetration-test results or exploitability, establish compliance, or rate an
organization's overall security.

The score is deterministic and reproducible for the same scoring version, check
versions, and normalized check observations. It is explainable at check and
category level, and counts a check's risk once rather than multiplying a
deduction by the number of similar observations. It only uses evidence observed
by WebGuard; unknown evidence is never silently interpreted as a pass or a
failure.

### Terminology

- **Finding severity** is the existing descriptive triage label (`critical`,
  `high`, `medium`, `low`, or `informational`). It helps people prioritize
  review; it is not a point value. `passed` is a legacy database severity value,
  not an in-memory scanner severity.
- **Finding status** is the check result (`pass`, `fail`, `warn`,
  `not_applicable`, or `error`). A status has check-specific scoring behavior.
- **Check weight** is the maximum number of score points assigned to one
  score-bearing check in this design. It is not severity.
- **Deduction** is the documented, capped point loss for a particular observed
  condition within one check.
- **Applicable weight** is the sum of the weights of expected score-bearing
  checks after removing only legitimate `not_applicable` checks.
- **Resolved weight** is the sum of applicable check weights with conclusive
  score evidence. Errors and inconclusive partial observations are not resolved.
- **Score confidence** describes coverage of the applicable scoring checks; it
  is reported separately from the numeric score.

## Selected methodology

WebGuard selects a **category-weighted, check-aware capped-deduction model**. It
is a hybrid: categories have fixed shares of the full 100-point budget, the
share is divided into documented check-level ceilings, and each check applies
its own evidence-specific deduction rules. This is not a severity-to-points
conversion.

| Model | Explainability | Stability / extensibility | Not-applicable / informational | Partial results / errors | Resistance to misleading scores |
| --- | --- | --- | --- | --- | --- |
| A. Flat weighted checks | Strong per-check explanation. | A new check can silently change the model or one domain can dominate without rebalancing. | Can exclude NA and zero-weight informational checks, but needs explicit rules. | Can exclude errors, but needs separate coverage/confidence rules. | Duplicate or numerous related checks can dominate the number. |
| B. Category-weighted checks | Clear category and check contributions. | Fixed category budgets limit drift; new checks require an explicit within-category allocation. | Can remove legitimate NA checks and leave informational checks at zero weight. | Needs a defined coverage mechanism in addition to category weighting. | More stable than flat checks, but category scores can still look definitive if scope is hidden. |
| C. Baseline with deductions | Intuitive “points lost” explanation. | Stable only while deductions and caps remain versioned. | Straightforward to omit NA/info checks if the denominator is carefully defined. | Missing checks can preserve the baseline unless errors affect eligibility or score availability. | A high baseline can overstate results when evidence is missing; overlapping deductions can over-penalize. |
| D. Pass rate | Simplest single-number explanation. | Changes when checks are added/removed; implicitly gives every check equal weight. | NA denominator handling is possible; informational checks can distort pass rate unless excluded. | Treating error as absent can raise the pass rate; treating it as fail penalizes the target for scanner failure. | Poor for unequal checks, partial results, and duplicate findings. |
| E. Hybrid (selected) | Explains category share, check ceiling, observed condition, and deduction. | Fixed category totals with explicit versioned check allocations. | Legitimate NA is excluded; passive technology/exposure observations are zero-weight. | Separate point and check-count coverage gates; errors remain unknown, not failures. | Capped check deductions, coverage gates, and explicit scope/confidence limit inflation from repetition or missing checks. |

The selected model takes the useful properties of B, C, and E: fixed category
budgets prevent check-count drift, a 100-point baseline makes deductions easy to
explain, and per-check rules prevent unrelated observations or severities from
being treated as equivalent. Option D is rejected because, for example, a
missing HSTS policy and a missing Permissions-Policy are not equal observations.

### Full-score point budget

These values were documentation-only during Phase 4D and are now frozen in the
Phase 4E scoring catalog. They remain product-priority allocations, not calibrated
risk probabilities.

| Category | Full-score share | Rationale |
| --- | ---: | --- |
| Transport | 30 | TLS protection of the observed final response is foundational to protecting data in transit. |
| Headers | 45 | CSP, HSTS, and frame restrictions provide distinct browser-side protections; the remaining policies are useful but more context-dependent. |
| Cookies | 15 | Cookie attributes matter, particularly for state-bearing cookies, but purpose is not reliably inferable from passive names and attributes. |
| Content | 10 | Mixed-content evidence can matter, but the scan only inspects a bounded captured HTML body and does not fetch or crawl resources. |
| **Total** | **100** | |

These are documented product-priority allocations, not empirically estimated
probabilities of compromise or calibrated vulnerability risk. The design places
the direct final-response transport check at 30; gives 35 of the header points
to broad/independent controls (CSP, HSTS, and frame protection) and 10 to
narrower/context-dependent policies; caps the aggregate cookie surface at 15
because cookie purpose is inferred imperfectly; and limits bounded passive
content inspection to 10. This basis makes the initial choices reviewable; it
does not make the score a scientific risk measurement. Do not retune allocations
to observed customer scores or target popularity. Review them against fixed
hypothetical/regression scenarios and issue a new scoring version if a scoring
result changes.

Only these check IDs receive non-zero allocations:

| Check ID | Category | Maximum deduction | Why this allocation is distinct |
| --- | --- | ---: | --- |
| `transport.https` | Transport | 30 | A response delivered over HTTP lacks transport protection for that response. |
| `headers.csp` | Headers | 14 | CSP can restrict resource execution/loading; presence alone is not proof of a safe policy. |
| `headers.hsts` | Headers | 12 | HSTS helps browsers remember to require HTTPS on later visits. |
| `headers.frame_protection` | Headers | 9 | Frame restrictions mitigate a separate class of deceptive embedding risks. |
| `headers.x_content_type_options` | Headers | 4 | `nosniff` is a narrower browser behavior control. |
| `headers.referrer_policy` | Headers | 3 | Referrer disclosure is useful to control, but observed policy strength is partly context-dependent. |
| `headers.permissions_policy` | Headers | 3 | Feature restriction is useful but highly application-specific. |
| `cookies.security_attributes` | Cookies | 15 | One aggregate budget covers the observed cookie set without charging per cookie. |
| `content.mixed_http_resources` | Content | 10 | The allocation is bounded to passive, partial page inspection; active resource types are more consequential than passive ones. |

The check ceilings sum to their category shares and to 100. A check's maximum is
a ceiling, not an automatic penalty for a finding. `transport.http_to_https_redirect`
and `transport.final_scheme` are deliberately diagnostic-only: with the current
check semantics, failure to upgrade an HTTP request overlaps the final HTTP
observation already scored by `transport.https`. Giving that same observation a
second deduction would double-count it. The redirect remains visible to users
and may be reconsidered only if a future check measures an independent property;
such a change would require a scoring-version update.

### Formula, rounding, and score availability

For the scoring check set, let `W` be the sum of applicable check weights,
`R` the sum of resolved applicable check weights, `N` the number of applicable
scoring checks, `K` the number of resolved scoring checks, and `D` the sum of
documented deductions for resolved checks. Legitimate `not_applicable` checks
are removed from both the weight and check-count denominators. Errors and
inconclusive checks remain in `W` and `N`, but are not in `R` or `K`. The
raw score is `100 × (R - D) / R`.

A numeric score is published only if both gates are met:

1. `W` is at least 60 points, so a very narrow applicable scope is not expanded
   into a misleading full-scale result.
2. Point coverage `R / W` is at least 80% **and** check-count coverage `K / N`
   is at least 80%. Requiring both prevents many low-point checks from being
   unavailable while the remaining high-point checks make the score appear
   complete.

If either gate fails, the score is unavailable (`null`), not zero. When a score
is available, it is normalized over the resolved applicable checks; the result
is therefore explicitly a score for the observed applicable scope, not a claim
that excluded checks passed. The UI/result explanation must show applicable and
resolved coverage, category scope, and all unassessed checks alongside it.

Weights and deductions are integer points. The normalized result may be
fractional; round exactly once at the end to the nearest whole point, with exact
half-points rounded **up** (decimal half-up, not language-default/banker's
rounding). Clamp only as a defensive final bound to **0–100 inclusive**. The
stored/displayed value is an integer because the UI says “OUT OF 100”
and `scans.score` is an integer type.

## Check inventory and scoring behavior

The inventory below is the current Phase 4B/4C registry, not the older database
catalog. Severity is descriptive and may vary with the specific outcome as
noted. All checks can return `error` when no response is available or the check
cannot complete. A check error has informational severity in the current
scanner and does not mean the target failed that check.

| Check ID | Name / category | What it measures | Possible statuses and severity | Score contribution and implemented behavior | Rationale and limitations |
| --- | --- | --- | --- | --- | --- |
| `transport.https` | HTTPS availability / Transport | Whether the final response URL uses HTTPS. | `pass`, `fail`, `error`; failure is high, pass/error informational. | **30 max.** `pass`: 0 deduction. `fail`: 30. `error`: unresolved, no deduction. | Directly observed transport on this request. It does not validate the whole TLS configuration or application security. |
| `transport.http_to_https_redirect` | HTTP-to-HTTPS redirect / Transport | Whether a request that started at HTTP recorded an upgrade to HTTPS and finished there. | `pass`, `fail`, `not_applicable`, `error`; failed is medium, other outcomes informational. | **Diagnostic only (0).** Retain result for explanation; do not add a second loss to `transport.https`. HTTPS start is legitimately not applicable. | Its current failed case overlaps a final HTTP response. It checks only the recorded chain, not every entry point or browser behavior. |
| `transport.final_scheme` | Final URL scheme / Transport | Records whether the validated final URL uses HTTP or HTTPS. | `pass`, `warn`, `error`; informational severity for all. | **Diagnostic only (0).** Its evidence helps explain the HTTPS check but is not an extra point-bearing check. | Redundant with `transport.https`; the final scheme does not establish application-level security. |
| `headers.hsts` | HTTP Strict Transport Security / Headers | On HTTPS, observes HSTS presence and parseable `max-age`, `includeSubDomains`, and `preload` tokens. | `pass`, `warn`, `fail`, `not_applicable`, `error`; weak/missing is medium, otherwise informational. | **12 max.** Missing header or explicit `max-age=0`: 12. Present but malformed/duplicated/incomplete directives: 6. Valid positive `max-age`: 0. `not_applicable` on final HTTP is excluded. | HSTS has a distinct future-visit benefit. It is meaningful only on HTTPS; this check does not determine preload eligibility or whether subdomains are safe to include. |
| `headers.csp` | Content Security Policy / Headers | Presence, basic structure, duplicate directives, and limited permissive source tokens. | `pass`, `warn`, `fail`, `error`; missing/weak/malformed is medium, passing is informational. | **14 max.** Missing policy: 14. `warn` with unsafe/broad sources: 9. Structural errors/duplicates only: 5. If both occur, use 9, not the sum. Parseable without these observed weaknesses: 0. | Higher allocation reflects CSP's broad defensive role. Parsing is intentionally limited; the check cannot prove policy completeness or safety. |
| `headers.x_content_type_options` | X-Content-Type-Options / Headers | Whether every observed value is `nosniff`. | `pass`, `fail`, `error`; failure low, otherwise informational. | **4 max.** Missing/unexpected value: 4; expected values: 0. Duplicate values are still one check result and one capped deduction. | Narrow browser behavior control; does not validate MIME types or all browser behavior. |
| `headers.referrer_policy` | Referrer Policy / Headers | Recognized policy tokens and the candidate effective policy in fallback lists. | `pass`, `warn`, `fail`, `error`; missing/ordinary warning low, `unsafe-url` warning medium, pass informational. | **3 max.** Missing: 3. `unsafe-url`: 3. Other warning (including malformed/unknown token or `no-referrer-when-downgrade`): 1. Multiple warning details use the highest applicable amount only. | Limits some referrer disclosure. The appropriate policy depends on product behavior and privacy needs. |
| `headers.permissions_policy` | Permissions Policy / Headers | Presence and basic syntax of directives/allowlists. | `pass`, `warn`, `fail`, `error`; missing/malformed low, pass informational. | **3 max.** Missing: 3. Present but malformed: 2. Parseable: 0. | Browser feature restrictions can be app-specific; syntax is not proof the policy is appropriate. |
| `headers.frame_protection` | Frame protection / Headers | Whether a recognized X-Frame-Options value or restrictive CSP `frame-ancestors` is observed. | `pass`, `warn`, `fail`, `error`; weak/missing medium, pass informational. | **9 max.** No recognized restriction: 9. Present but unrecognized/ineffective X-Frame-Options with no restrictive CSP: 5. A recognized protection by either supported mechanism: 0. | One check intentionally treats X-Frame-Options and CSP as equivalent ways to observe protection; do not deduct once per header. It cannot verify application-specific embedding needs. |
| `exposure.server_headers` | Server information exposure / Exposure | Whether `Server` or `X-Powered-By` identifies a server/framework, and whether a version-like token is disclosed. | `pass`, `warn`, `error`; warning is low when a version is recognized, otherwise informational; pass/error informational. | **Informational only (0).** Never deduct for an identifier or version string alone. | Disclosure can aid reconnaissance but is not itself a vulnerability; scanner does not verify version currency or exploitability. |
| `cookies.security_attributes` | Cookie security attributes / Cookies | Value-free observed cookie attributes: Secure, heuristic HttpOnly candidates, SameSite, scope, prefixes, and selected attribute validity. | `pass`, `warn`, `not_applicable`, `error`; direct Secure/`SameSite=None` issues medium, other review items low, pass/NA/error informational. | **15 max, aggregated.** Apply 10 once if any HTTPS cookie lacks Secure or any `SameSite=None` cookie lacks Secure; add 5 once if any prefix requirement or outside/invalid domain-scope violation is observed; add 3 once for any advisory class (missing/invalid SameSite, sensitive-name HttpOnly candidate, malformed Set-Cookie, or invalid parsed attribute); cap at 15. No Set-Cookie headers is legitimate `not_applicable`. | One budget for the whole observed cookie set prevents a 50-cookie response from becoming 50 times worse. Cookie names are only purpose hints; cookies set elsewhere or after this response are not observed, and values are discarded. |
| `content.mixed_http_resources` | Mixed-content references / Content | A bounded inspection of captured HTTPS HTML/XHTML for absolute HTTP resource references; no subresources are fetched. | `pass`, `warn`, `not_applicable`, `error`; active references high, passive references low, truncated/no-hit warning informational, pass/NA/error informational. | **10 max, aggregated.** Any observed active resource type (script, stylesheet, frame/iframe, embed, object): 10. Passive references only: 5. Multiple references do not multiply the deduction. Complete inspection with no references: 0. Incomplete inspection with no hit is unresolved, not a pass. | Active and passive references differ in potential impact, but the scanner inspects only selected attributes in a bounded prefix; it omits inline CSS URLs, `srcset`, arbitrary script behavior, and other syntax. |
| `technology.passive_indicators` | Passive technology indicators / Technology | A finite allowlist of already-captured header and HTML indicators and their passive confidence. | `pass`, `error`; informational severity. | **Informational only (0).** A detected or absent technology signal never affects the score. | Detection is incomplete and passive; technology presence is not a vulnerability and should not reward or penalize a particular stack. |

### Exact check-level deduction table

This compact table is the rule of record for outcomes with a non-zero ceiling.
Finding severity is intentionally absent from the arithmetic.

| Check | Observed evidence | Deduction |
| --- | --- | ---: |
| `transport.https` | Final response uses HTTP | 30 |
| `headers.hsts` | Header absent on HTTPS, or explicit `max-age=0` | 12 |
| `headers.hsts` | Header present but parse errors/duplicates/missing required parseable directive, other than explicit zero above | 6 |
| `headers.csp` | No policy | 14 |
| `headers.csp` | One or more observed unsafe/broad tokens | 9 |
| `headers.csp` | Structural/duplicate issue only | 5 |
| `headers.frame_protection` | No recognized restriction | 9 |
| `headers.frame_protection` | Unrecognized/ineffective X-Frame-Options warning, without restrictive CSP | 5 |
| `headers.x_content_type_options` | Missing or unexpected value | 4 |
| `headers.referrer_policy` | Missing or `unsafe-url` candidate | 3 |
| `headers.referrer_policy` | Other warning | 1 |
| `headers.permissions_policy` | Missing | 3 |
| `headers.permissions_policy` | Present but malformed | 2 |
| `cookies.security_attributes` | At least one Secure-missing-on-HTTPS or `SameSite=None`-without-Secure observation | +10 once per scan/check |
| `cookies.security_attributes` | At least one prefix violation or outside/invalid domain-scope observation | +5 once per scan/check |
| `cookies.security_attributes` | At least one advisory observation listed above | +3 once per scan/check |
| `cookies.security_attributes` | Sum of cookie classes exceeds check ceiling | Cap total at 15 |
| `content.mixed_http_resources` | Any observed active reference | 10 |
| `content.mixed_http_resources` | Passive references only | 5 |

For CSP, Referrer-Policy, and frame protection, use the highest matching outcome
for that check, not a sum of duplicate or overlapping evidence. For cookies, add
at most one amount per distinct issue class and cap the aggregate. For content,
use the strongest observed resource class; do not scale with the count of
references, origins, or tags. Every deduction is bounded by the check maximum.

## Status, applicability, and incomplete results

| Result condition | Numeric treatment | Confidence / explanation treatment |
| --- | --- | --- |
| `pass` with sufficient evidence | Zero deduction; its weight is resolved. | Counts as observed evidence; explain the control as meeting this check's limited observed condition, not proof of safety. |
| `fail` | Apply only the check-specific deduction above; its weight is resolved. | Show the check and concrete observed reason. |
| `warn` with a mapped, observed weakness | Apply the check-specific warning rule; its weight is resolved. | Preserve warning details and evidence. `warn` is not globally a partial deduction class. |
| `warn` caused only by bounded/truncated observation with no positive hit | No deduction; do not treat it as pass. It is unresolved and not in resolved weight. | Mark the check incomplete and reduce score coverage. |
| Legitimate `not_applicable` | No deduction; remove the check's weight from applicable weight and resolved-weight calculation. | Explain why it does not apply. Examples: HTTP-to-HTTPS redirect check on an HTTPS-start URL (diagnostic only), HSTS on final HTTP, cookies when no Set-Cookie was observed, mixed content for non-HTTPS or unambiguously non-HTML response. |
| `not_applicable` because required captured evidence is missing/incomplete | Do not deduct and do not count as resolved; keep it in applicable weight. | Treat as unknown/incomplete, not as legitimate scope-based NA. In particular, an incomplete HTML body is not evidence of no mixed content. |
| `error` | No deduction and not in resolved weight; keep applicable weight in the coverage denominator. | Reduce coverage. Errors distinguish scanner/check failure from an observed target weakness. |
| Missing expected score-check result | Same as unresolved/error: no deduction, not resolved, remains applicable. | Explicitly list the missing check; do not infer pass. |

For the score-specific confidence label (both coverage ratios must meet the
stated band):

- **Complete:** at least 60 applicable points and all applicable score-bearing
  checks are resolved (`R/W = 100%` and `K/N = 100%`), with no score-relevant
  evidence truncation.
- **Partial:** at least 60 applicable points and both coverage ratios are at
  least 80%, but some applicable check is unresolved or relevant evidence is
  explicitly partial. A numeric score may be shown; it is normalized over
  resolved applicable checks and must be labelled partial with unresolved checks
  and both coverage ratios visible.
- **Limited:** fewer than 60 applicable points, either coverage ratio below 80%,
  no captured response for the score checks, or otherwise insufficient scoring
  evidence. Do not publish a numeric score (`score: null`); this is not a zero.

Confidence is not multiplied into, subtracted from, or otherwise blended into the
number. The availability gates are solely to withhold results that have too
little evidence. A complete score can still be limited to this product's
checklist and observations; “complete” is not a claim of complete security
coverage.

## Categories and non-scoring observations

The score categories and fixed full-scope budgets are Transport (30), Headers
(45), Cookies (15), and Content (10). The Exposure and Technology categories
remain visible in findings/technology context but have no score allocation.
Their existence, absence, or scan error cannot raise or lower the number.

Within a category, category detail should show the deductions and the applicable,
resolved, and unassessed portion. If no point-bearing check applies, show the
category as not applicable. If only some category checks resolve, show it as
partial rather than presenting an apparently complete category score. Since
check N/A and error states alter the observed scope, category subtotals are
explanations, not an independently comparable benchmark unless their scope and
confidence match.

## Multiple observations and duplicate-penalty controls

Phase 4B/4C checks currently return one aggregate `Finding` per check. Scoring
retains that aggregation:

- Cookie count, duplicate cookie weaknesses, and repeated names do not multiply a
  check deduction. Distinct observed issue classes can add only within the
  cookie check's 15-point cap.
- CSP tokens, malformed directives, and duplicate header values use the
  check-specific strongest-outcome rule rather than one deduction per token or
  header.
- X-Frame-Options and CSP `frame-ancestors` are one check; either recognized
  protection avoids a missing-protection deduction.
- Mixed-content references use the strongest observed active/passive class, not
  a per-URL, per-origin, or per-tag count. The current reference-count bounds
  affect explanation, not penalty size.
- Server headers and technology indicators never multiply or offset other
  deductions.

An implementation must not turn one aggregate check into a list of separately
penalized rows. If future requirements need per-object findings, aggregation and
the one-check cap remain unless a separately versioned methodology deliberately
changes that rule.

## Phase 4E engine and catalog reconciliation

`backend/app/scanner/scoring.py` implements this design as `score_findings()`.
It consumes canonical `Finding` objects only; it does not read a `ScanContext`,
perform network or filesystem operations, or persist anything. The one
authoritative code constant is `SCORING_VERSION = "1.0"`. Check version `"1"`
and the point-bearing catalog are defined alongside the scoring rules. The
module returns an immutable `ScoreResult` with the score (or `null`), confidence,
applicable/resolved points and check counts, coverage percentages, category
breakdowns, check-level reason codes/conditions/evidence references, and
unavailability reasons. `ScoreResult.to_dict()` is the JSON-friendly shape for a
future API or persisted snapshot; it is not currently served by an endpoint.

The canonical in-memory catalog contains all 13 current scanner IDs. Nine have
non-zero weights and participate in coverage; two transport checks are
diagnostic-only; exposure and technology are informational-only. The legacy
catalog correspondences are explicit and are never runtime aliases:

| Existing `scan_checks.check_id` | Canonical scanner ID | Reconciliation |
| --- | --- | --- |
| `https` | `transport.https` | Same observed final-response HTTPS property |
| `http_to_https` | `transport.http_to_https_redirect` | Recorded HTTP-to-HTTPS upgrade; canonical check remains diagnostic-only |
| `hsts` | `headers.hsts` | Same HSTS response-header observation |
| `csp` | `headers.csp` | Same CSP response-header observation |
| `x_content_type_options` | `headers.x_content_type_options` | Same header observation |
| `referrer_policy` | `headers.referrer_policy` | Same header observation |
| `permissions_policy` | `headers.permissions_policy` | Same header observation |
| `frame_protection` | `headers.frame_protection` | Same combined X-Frame-Options/CSP observation |
| `secure_cookies` | `cookies.security_attributes` | Same aggregate cookie-attribute observation |
| `server_header` | `exposure.server_headers` | Same passive disclosure observation; canonical category is `exposure`, not legacy `headers` |
| `mixed_content` | `content.mixed_http_resources` | Same bounded passive HTML observation |
| *(no legacy row)* | `transport.final_scheme` | New diagnostic-only result; no legacy alias |
| *(no legacy row)* | `technology.passive_indicators` | New informational-only result; no legacy alias |

The engine accepts only the 13 canonical dotted IDs and raises on unknown or
legacy IDs rather than silently guessing. It always expects all nine
score-bearing results; missing ones remain applicable and unresolved. Identical
duplicate findings collapse to one result. Conflicting duplicates make that
check unresolved instead of selecting a pass/fail or accumulating deductions.

Status interpretation is explicit and evidence-aware:

| Status | Engine behavior |
| --- | --- |
| `pass` | Zero deduction and resolved only when the check's required evidence agrees with a conclusive pass; missing or contradictory evidence is unresolved. |
| `fail` | Apply only that check's documented failure rule when its evidence supports the condition; otherwise unresolved. |
| `warn` | Apply a mapped check-specific warning deduction when the evidence identifies a weakness. A mixed-content no-hit truncation remains unresolved, not a pass. |
| `not_applicable` | Exclude the weight only for documented legitimate scope exclusions: HSTS on final HTTP, no captured Set-Cookie headers, or mixed-content checks on final HTTP/known non-HTML. Incomplete HTML or unknown evidence stays applicable and unresolved. |
| `error` | No deduction; keep the check applicable and unresolved, reducing coverage. |

An available score requires at least 60 applicable points, at least 80% resolved
point coverage, and at least 80% resolved check-count coverage. Unresolved evidence
is listed as `incomplete_scan` when it contributes to withholding the number; it
does not automatically withhold a score when both coverage gates still pass.
Confidence is `complete` for a fully resolved, non-partial observation; `partial`
for an available score with qualifying unresolved or explicitly truncated
evidence; and `limited` whenever a gate withholds the numeric result. Confidence
never modifies the arithmetic. Category output distinguishes full category
budget, applicable/resolved/unassessed points, deductions, resulting observed
points, and `complete`/`partial`/`not_applicable` state.

With the current nine weighted checks and documented legitimate exclusions, the
smallest applicable scope is 63 points (HTTP final response, no observed cookies,
and HSTS/content not applicable). The 60-point gate is retained as a defensive
methodology rule for future catalog evolution and its below-threshold branch is
unit-tested directly.

For deterministic presentation, check explanations sort by deduction descending,
then descriptive severity order, then canonical check ID. `weakest_categories`
lists categories with deductions, sorted by their deduction share of resolved
category points (largest share first; fixed category order breaks ties). Severity
and weakest-category ordering are presentation metadata only; neither changes the
score.

## Score explanation contract

The in-memory result exposes enough structured data to explain the number without
reconstructing vague severity weights. It includes:

- score integer or unavailable; `scoring_version`; confidence label;
- applicable/resolved point weights and point coverage, plus applicable/resolved
  check counts and check-count coverage;
- category summaries with applicable/resolved points, deductions, and complete,
  partial, or not-applicable state;
- for each scoring check: stable `check_id`, `check_version`, status, severity
  (descriptive only), points available, actual deduction, concise reason, and
  evidence reference;
- explicit non-scoring / not-applicable / error checks and reasons;
- passed checks as “points retained”/observed controls, not bonus points;
- reduced checks sorted by numeric impact first, then severity as a display-only
  tie-breaker, then stable check ID for deterministic ordering;
- `weakest_categories` and a clear message when a category could not be evaluated.

The result should make clear what contributed positively (resolved checks with
no deduction), what reduced the score (check-specific deductions), what remains
unknown, and what checks were out of scope. A high score must never be described
as “secure,” “safe,” or equivalent.

## Versioning and compatibility

The initial methodology identifier is **`scoring_version = "1.0"`**. It binds
the category/check point allocations, outcome rules, applicability rules,
coverage gates, confidence labels, formula, and rounding behavior. Any change
that can change a score or its availability gets a new scoring version; do not
silently reinterpret historical results. Historical scores retain the version
under which they were produced. Re-scoring old evidence is an explicit,
separately stored result under a new version, never an overwrite.

Existing scanner check IDs are stable API/data identifiers and must not be
renamed. The 13 current IDs are exactly those inventoried above. Phase 4E assigns
each a stable independent `check_version` of `"1"`. Bump that version when the
meaning, status behavior, evidence interpretation, or coverage bounds materially change.
The scoring version and each check version are separate: a check can evolve
without relabelling history, but a score-affecting interpretation change must
also select a new compatible scoring version. For replay, preserve the scoring
version, check versions, normalized statuses, and the evidence used for the
decision; a version label alone cannot recreate discarded evidence.

## Database compatibility observations

The Phase 4D/4E review inspected both
`supabase/migrations/20260927123015_webguard_schema.sql` and the live WebGuard
Supabase project (`akubhdfghktuynsncdfx`) read-only. Migration version
`20260927123015` is recorded in the live migration history. At inspection, the
live catalog had 11 rows and `scans`/`findings` had no rows. Phase 4E made no
database changes; the Phase 4F migration below has not yet been applied remotely.

- `public.scans.score` is nullable `smallint` constrained to 0–100, compatible
  with a whole-number score and `null` when confidence is limited. `scans` has no
  scoring version, confidence, coverage, or category/check explanation fields.
- `public.findings` has `scan_id`, `check_id`, title, severity, status,
  description, JSONB evidence, recommendation, and a unique `(scan_id, check_id)`
  constraint. That uniqueness is compatible with today's one aggregate finding
  per check; Phase 4E also deterministically collapses identical in-memory
  duplicates and marks conflicting ones unresolved. Its status constraint allows
  `passed`, `failed`, `not_applicable`, and `error`, while scanner findings use
  `pass`, `fail`, `warn`, `not_applicable`, and `error`. The Phase 4F migration
  normalizes legacy values before enforcing the canonical statuses; it does not
  overload severity with the legacy `passed` value.
- `public.scan_checks` has descriptive metadata and `default_severity`, but no
  check version or scoring allocations. The live catalog contains 11 legacy IDs
  (`https`, `http_to_https`, `hsts`, `csp`, `x_content_type_options`,
  `referrer_policy`, `permissions_policy`, `frame_protection`,
  `secure_cookies`, `server_header`, `mixed_content`). The scanner registry has
  13 stable dotted IDs: `transport.https`,
  `transport.http_to_https_redirect`, `transport.final_scheme`,
  `headers.hsts`, `headers.csp`, `headers.x_content_type_options`,
  `headers.referrer_policy`, `headers.permissions_policy`,
  `headers.frame_protection`, `exposure.server_headers`,
  `cookies.security_attributes`, `content.mixed_http_resources`, and
  `technology.passive_indicators`. The explicit 11-to-11 correspondence and two
  new canonical IDs are listed in the Phase 4E reconciliation table above and in
  `LEGACY_CATALOG_RECONCILIATION` in the scoring module. Do not rename scanner
  IDs or accept the legacy IDs as scoring aliases.
- In the legacy seed, `server_header` is categorized as `headers`; the current
  registry classifies `exposure.server_headers` as `exposure`. Use the current
  check category in score explanations and resolve catalog drift explicitly.
- RLS is enabled on the inspected `scans`, `findings`, and `scan_checks` tables.

Phase 4E made no schema change. Phase 4F records the approved integration in
`supabase/migrations/20260928120000_phase4f_scan_pipeline.sql`; that migration is
applied to the hosted project. Read-only verification confirmed the canonical
catalog, scoring persistence schema, and ownership RLS. The pgTAP suites have not
been executed because local database tooling is unavailable.

The Phase 4F migration preserves all 11 legacy rows and seeds one canonical row
for each of the 13 scanner IDs. `scan_checks.is_canonical` distinguishes current
runtime IDs; `legacy_check_id` on the canonical row explicitly records its
legacy correspondence, including `server_header` → `exposure.server_headers`.
Legacy records/findings are not renamed or deleted, and runtime scoring never
accepts legacy aliases. `ON CONFLICT (check_id)` makes canonical seeding
idempotent.

The migration normalizes legacy finding statuses (`passed` → `pass`, `failed` →
`fail`) and legacy severity `passed` → `informational`, then enforces exactly the
five scanner statuses: `pass`, `fail`, `warn`, `not_applicable`, and `error`.
The scan lifecycle is constrained to `pending`, `running`, `completed`, and
`failed`. No arbitrary status text is admitted.

Scoring storage keeps the existing nullable 0–100 `scans.score` and adds
`score_available`, nullable `scoring_version`, controlled `score_confidence`, and
versioned `score_details` JSONB. The details JSON contains point/check coverage,
category breakdown, weakest categories, deductions, and unavailable reason
codes; the scalar/version/confidence fields are not duplicated inside it. Each
`scan_check_results` row stores the check's evidence/status and its
`score_explanation` JSONB, so the list of check explanations is not duplicated in
`scans.score_details`. Mutable point weights remain out of the global catalog;
the stored score explanation is the versioned snapshot needed to interpret the
result.

The existing `findings.description` and `recommendation` columns are reused for
scanner summary and remediation. The migration adds the missing
`why_it_matters`, query-stripped `affected_url`, and JSONB `metadata` fields. For
technology records, `confidence_label` stores the exact scanner category while
the established numeric confidence is retained as a compatibility projection:
low `0.4`, medium `0.7`, and high `0.9`. Evidence is a bounded list of passive
signal names, never a response body.

The privileged RPC `public.persist_completed_scan` runs the result inserts and
transition to `completed` in one Postgres transaction. It is a `SECURITY INVOKER`
function with an empty search path and executable only by `service_role`; it uses
the service role's existing grants (without elevating privileges) and checks the
running scan owner and complete canonical check inventory. Scan row
creation and the running transition are earlier independent REST requests. If
the completion RPC fails, its inserts/status update roll back and the API tries
to mark the scan failed. A total Supabase outage can prevent that final status
update, which is an acknowledged multi-request lifecycle limitation.

## Worked examples

All examples use hypothetical data, not real websites. They describe the v1.0
rules implemented in Phase 4E and are regression cases in `backend/tests/test_scoring.py`.

### 1. Strong observed configuration

**Hypothetical ScanContext:** request and final URL are HTTPS; an HTTP response
was captured; HSTS has positive parseable `max-age`; CSP is parseable without
the limited flagged weak tokens; X-Content-Type-Options is `nosniff`; Referrer
and Permissions policies are parseable; frame protection is present through
`frame-ancestors`; one observed cookie has Secure, HttpOnly, and SameSite; the
complete captured HTML has no detected absolute HTTP resource attributes.

| Score check | Result | Deduction |
| --- | --- | ---: |
| `transport.https` | pass | 0 / 30 |
| All six scored header checks | pass | 0 / 45 |
| `cookies.security_attributes` | pass | 0 / 15 |
| `content.mixed_http_resources` | pass | 0 / 10 |

All 100 applicable points resolve, so `R=100`, `D=0`, point coverage is 100%,
and check-count coverage is `K/N = 9/9`. The score is **100/100**, and
confidence is **complete**. The HTTP-to-HTTPS redirect
check is `not_applicable` because the request started at HTTPS, but it is
diagnostic-only and does not change the score. This result means only that no
deduction was observed among this applicable checklist; it does not establish
that the site is secure.

### 2. Mixed observed configuration

**Hypothetical ScanContext:** request and final URL are HTTP; an HTTP response
was captured; CSP, X-Content-Type-Options, Permissions-Policy, and frame
protection are absent; Referrer-Policy is `unsafe-url`; one observed cookie uses
`SameSite=None` without Secure; no cookie values are retained. The response is
not HTTPS HTML.

| Score check | Result | Deduction |
| --- | --- | ---: |
| `transport.https` | fail | 30 / 30 |
| `headers.hsts` | not applicable on final HTTP | excluded (12) |
| `headers.csp` | fail, absent | 14 / 14 |
| `headers.x_content_type_options` | fail | 4 / 4 |
| `headers.referrer_policy` | warn, `unsafe-url` | 3 / 3 |
| `headers.permissions_policy` | fail | 3 / 3 |
| `headers.frame_protection` | fail | 9 / 9 |
| `cookies.security_attributes` | warn, `SameSite=None` without Secure | 10 / 15 |
| `content.mixed_http_resources` | not applicable on non-HTTPS response | excluded (10) |

The HTTP redirect check also fails, but is diagnostic-only and does not add a
second transport deduction. Applicable weight is `W=78` (30 transport + 33
headers + 15 cookies); resolved weight is `R=78`; check-count coverage is
`K/N = 7/7`; `D=73`. The raw result is
`100 × (78 - 73) / 78 = 6.410…`, rounded half-up to **6/100**, with **complete**
score confidence for the applicable scope. The excluded HSTS/content checks are
reported as out of scope, not as successful checks.

### 3. Partial / incomplete scan

**Hypothetical ScanContext:** request and final URL are HTTPS and a response was
captured. HTTPS, HSTS, X-Content-Type-Options, Referrer-Policy,
Permissions-Policy, and frame checks resolve as pass. CSP check returns error;
cookie metadata extraction also errors, so the scanner cannot conclude whether
Set-Cookie headers existed. The HTML body is incomplete and produced no
mixed-content hit.

| Scoring group | Applicable points | Resolved points | State |
| --- | ---: | ---: | --- |
| Transport | 30 | 30 | resolved |
| Headers | 45 | 31 | CSP unresolved; other five scored header checks resolved |
| Cookies | 15 | 0 | error / unresolved |
| Content | 10 | 0 | incomplete body / unresolved, not pass |
| **Total** | **100** | **61** | |

Point coverage is 61% (`R/W = 61/100`) and check-count coverage is 67%
(`K/N = 6/9`), both below the 80% publication gate. Confidence is **limited**
and the numeric score is **unavailable (`null`)**, not 0 and not 100. The report can
still explain which checks passed, identify the CSP/cookie errors and incomplete
body, and state that those checks made no score deduction because they produced
no conclusion. It must not infer that missing evidence is safe.

For contrast, if the same HTTPS response had only an incomplete no-hit content
check and no Set-Cookie headers (a legitimate cookie `not_applicable`), then
`W=85`, `R=75`, `N=8`, and `K=7`: point coverage is 88.2% and check-count
coverage is 87.5%. If all seven resolved checks pass, the normalized number is
**100/100 with partial confidence**, not complete confidence. The missing content
check is prominently listed; the number is not described as covering it.

## Limitations and future review

The score is a deliberately narrow configuration signal based on one bounded
response context. It does not crawl routes, execute JavaScript, fetch
subresources, authenticate as different users, infer business logic, validate
the full TLS posture, establish cookie purpose, or assess all CSP/Permissions
Policy semantics. Results can vary with requested route, response state,
redirects, user-agent differences, transient failures, or unseen content. The
scan is point-in-time; historical comparisons should require matching scoring
versions and show confidence/scope changes rather than suggesting algorithmic
trend continuity.

Revisit allocations only with a documented product rationale and representative
tests. Preserve old scoring versions, never use severity labels as a shortcut,
and stop short of claims that exceed the evidence collected.
