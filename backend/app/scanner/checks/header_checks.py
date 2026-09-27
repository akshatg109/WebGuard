"""Deterministic passive checks for the captured response headers."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from app.scanner.checks.base import BaseCheck
from app.scanner.checks.headers import (
    header_values,
    parse_csp,
    parse_hsts,
    parse_permissions_policy,
    recognized_referrer_policies,
)
from app.scanner.findings import Finding, FindingCategory, FindingStatus, Severity
from app.scanner.models import ScanContext


class HstsCheck(BaseCheck):
    check_id = "headers.hsts"
    name = "HTTP Strict Transport Security"
    description = "Observes HSTS presence and the parseable max-age/includeSubDomains/preload directives."
    category = FindingCategory.HEADERS
    default_severity = Severity.MEDIUM
    default_why_it_matters = "Without active HSTS, browsers may not remember to require HTTPS on later visits."
    default_remediation = "Configure HSTS on HTTPS responses with a deliberate max-age; review subdomain and preload effects before enabling them."

    def run(self, context: ScanContext) -> tuple[Finding, ...]:
        unavailable = self.response_error(context)
        if unavailable is not None:
            return (unavailable,)
        scheme = _scheme(context.current_url)
        if scheme != "https":
            return (
                self.finding(
                    context,
                    status=FindingStatus.NOT_APPLICABLE,
                    severity=Severity.INFORMATIONAL,
                    summary="HSTS is only observed on HTTPS responses; the final response used HTTP.",
                    evidence={"final_scheme": scheme, "header_present": bool(header_values(context, "strict-transport-security"))},
                ),
            )

        values = header_values(context, "strict-transport-security")
        if not values:
            return (
                self.finding(
                    context,
                    status=FindingStatus.FAIL,
                    severity=self.default_severity,
                    summary="No Strict-Transport-Security header was observed on the HTTPS response.",
                    evidence={"header_present": False, "final_scheme": scheme},
                ),
            )

        parsed = parse_hsts(values)
        evidence = {
            "header_present": True,
            "header_count": len(values),
            "max_age": parsed.max_age,
            "include_subdomains": parsed.include_subdomains,
            "preload_token_present": parsed.preload,
            "preload_eligibility_checked": False,
            "parse_errors": parsed.errors,
            "final_scheme": scheme,
        }
        if parsed.errors:
            status = FindingStatus.WARN
            severity = self.default_severity
            summary = "Strict-Transport-Security was observed, but one or more directives are missing, duplicated, or malformed."
        elif parsed.max_age == 0:
            status = FindingStatus.FAIL
            severity = self.default_severity
            summary = "The HSTS max-age is zero, which instructs browsers to stop enforcing HSTS."
        else:
            status = FindingStatus.PASS
            severity = Severity.INFORMATIONAL
            summary = "HSTS is present with a parseable positive max-age; preload eligibility and application security were not assessed."
        return (self.finding(context, status=status, severity=severity, summary=summary, evidence=evidence),)


class ContentSecurityPolicyCheck(BaseCheck):
    check_id = "headers.csp"
    name = "Content Security Policy"
    description = "Observes CSP presence, directive structure, and several permissive source tokens."
    category = FindingCategory.HEADERS
    default_severity = Severity.MEDIUM
    default_why_it_matters = "A CSP can constrain resource loading and reduce the impact of some injection mistakes, but its correctness is application-specific."
    default_remediation = "Define and test a Content-Security-Policy appropriate for the application; header presence alone is not proof of a safe policy."

    def run(self, context: ScanContext) -> tuple[Finding, ...]:
        unavailable = self.response_error(context)
        if unavailable is not None:
            return (unavailable,)
        values = header_values(context, "content-security-policy")
        if not values:
            return (
                self.finding(
                    context,
                    status=FindingStatus.FAIL,
                    severity=self.default_severity,
                    summary="No Content-Security-Policy header was observed.",
                    evidence={"header_present": False},
                ),
            )

        parsed = parse_csp(values)
        evidence: dict[str, object] = {
            "header_present": True,
            "header_count": len(values),
            "directive_names": parsed.directive_names,
            "default_src_present": "default-src" in parsed.directive_names,
            "unsafe_inline_observed": parsed.unsafe_inline,
            "unsafe_eval_observed": parsed.unsafe_eval,
            "broad_source_kinds": parsed.broad_sources,
            "malformed_policy_count": len(parsed.malformed_policy_indexes),
            "duplicate_directives": parsed.duplicate_directives,
        }
        has_weak_elements = parsed.unsafe_inline or parsed.unsafe_eval or bool(parsed.broad_sources)
        if parsed.malformed_policy_indexes or parsed.duplicate_directives:
            status = FindingStatus.WARN
            severity = self.default_severity
            summary = "A Content-Security-Policy header is present, but malformed policies or duplicate directives were observed."
        elif has_weak_elements:
            status = FindingStatus.WARN
            severity = self.default_severity
            summary = "CSP contains permissive source tokens; header presence alone does not establish policy strength."
        else:
            status = FindingStatus.PASS
            severity = Severity.INFORMATIONAL
            summary = "CSP is present and structurally parseable; this check does not prove that the policy is complete or safe."
        return (self.finding(context, status=status, severity=severity, summary=summary, evidence=evidence),)


class XContentTypeOptionsCheck(BaseCheck):
    check_id = "headers.x_content_type_options"
    name = "X-Content-Type-Options"
    description = "Checks whether all observed values use the nosniff token."
    category = FindingCategory.HEADERS
    default_severity = Severity.LOW
    default_why_it_matters = "MIME sniffing can cause browsers to interpret a response differently from its declared content type."
    default_remediation = "Set X-Content-Type-Options to nosniff."

    def run(self, context: ScanContext) -> tuple[Finding, ...]:
        unavailable = self.response_error(context)
        if unavailable is not None:
            return (unavailable,)
        values = header_values(context, "x-content-type-options")
        normalized = tuple(value.casefold() for value in values)
        correct = bool(values) and all(value == "nosniff" for value in normalized)
        return (
            self.finding(
                context,
                status=FindingStatus.PASS if correct else FindingStatus.FAIL,
                severity=Severity.INFORMATIONAL if correct else self.default_severity,
                summary=(
                    "X-Content-Type-Options is present with the expected nosniff value."
                    if correct
                    else "X-Content-Type-Options is missing or does not use the expected nosniff value."
                ),
                evidence={
                    "header_present": bool(values),
                    "header_count": len(values),
                    "expected_value": "nosniff",
                    "nosniff_values": sum(value == "nosniff" for value in normalized),
                    "unexpected_value_count": sum(value != "nosniff" for value in normalized),
                },
            ),
        )


class ReferrerPolicyCheck(BaseCheck):
    check_id = "headers.referrer_policy"
    name = "Referrer Policy"
    description = "Recognizes standard Referrer-Policy tokens and reports weaker recognized values without assuming app requirements."
    category = FindingCategory.HEADERS
    default_severity = Severity.LOW
    default_why_it_matters = "Referrer-Policy controls how much URL information browsers may send to other origins."
    default_remediation = "Choose a Referrer-Policy that matches the application's privacy and navigation requirements."

    def run(self, context: ScanContext) -> tuple[Finding, ...]:
        unavailable = self.response_error(context)
        if unavailable is not None:
            return (unavailable,)
        values = header_values(context, "referrer-policy")
        if not values:
            return (
                self.finding(
                    context,
                    status=FindingStatus.FAIL,
                    severity=self.default_severity,
                    summary="No Referrer-Policy header was observed.",
                    evidence={"header_present": False},
                ),
            )

        recognized, unknown = recognized_referrer_policies(values)
        selected = recognized[-1] if recognized else None
        weak = selected in {"unsafe-url", "no-referrer-when-downgrade"}
        malformed = not recognized or bool(unknown)
        if malformed:
            status = FindingStatus.WARN
            severity = self.default_severity
            summary = "A Referrer-Policy header is present, but no valid token was observed or unrecognized tokens were included."
        elif weak:
            status = FindingStatus.WARN
            severity = Severity.MEDIUM if selected == "unsafe-url" else self.default_severity
            summary = "The recognized policy may send more referrer information than some applications intend."
        else:
            status = FindingStatus.PASS
            severity = Severity.INFORMATIONAL
            summary = "A standard Referrer-Policy token was observed; application-specific privacy requirements were not assessed."
        return (
            self.finding(
                context,
                status=status,
                severity=severity,
                summary=summary,
                evidence={
                    "header_present": True,
                    "header_count": len(values),
                    "recognized_policies": recognized,
                    "effective_policy_candidate": selected,
                    "weaker_policy_candidate": weak,
                    "unrecognized_token_count": len(unknown),
                },
            ),
        )


class PermissionsPolicyCheck(BaseCheck):
    check_id = "headers.permissions_policy"
    name = "Permissions Policy"
    description = "Checks Permissions-Policy presence and basic directive/allowlist syntax."
    category = FindingCategory.HEADERS
    default_severity = Severity.LOW
    default_why_it_matters = "Permissions-Policy can restrict browser capabilities that a page or embedded frame may use."
    default_remediation = "Define a Permissions-Policy for browser capabilities that the application does not need."

    def run(self, context: ScanContext) -> tuple[Finding, ...]:
        unavailable = self.response_error(context)
        if unavailable is not None:
            return (unavailable,)
        values = header_values(context, "permissions-policy")
        if not values:
            return (
                self.finding(
                    context,
                    status=FindingStatus.FAIL,
                    severity=self.default_severity,
                    summary="No Permissions-Policy header was observed.",
                    evidence={"header_present": False},
                ),
            )
        directives, malformed, errors = parse_permissions_policy(values)
        return (
            self.finding(
                context,
                status=FindingStatus.WARN if malformed else FindingStatus.PASS,
                severity=self.default_severity if malformed else Severity.INFORMATIONAL,
                summary=(
                    "Permissions-Policy is present but its directive structure could not be fully parsed."
                    if malformed
                    else "Permissions-Policy is present and structurally parseable; application-specific correctness was not assessed."
                ),
                evidence={
                    "header_present": True,
                    "header_count": len(values),
                    "directive_names": directives,
                    "parse_errors": errors,
                },
            ),
        )


class FrameProtectionCheck(BaseCheck):
    check_id = "headers.frame_protection"
    name = "Frame protection"
    description = "Observes X-Frame-Options and CSP frame-ancestors without duplicating equivalent protection."
    category = FindingCategory.HEADERS
    default_severity = Severity.MEDIUM
    default_why_it_matters = "Unrestricted framing can allow another site to embed the page in a deceptive interface."
    default_remediation = "Set CSP frame-ancestors to the intended allowed framing origins; consider X-Frame-Options for legacy compatibility."

    def run(self, context: ScanContext) -> tuple[Finding, ...]:
        unavailable = self.response_error(context)
        if unavailable is not None:
            return (unavailable,)

        xfo_values = header_values(context, "x-frame-options")
        xfo_valid = len(xfo_values) == 1 and xfo_values[0].casefold() in {"deny", "sameorigin"}
        xfo_allow_from = any(
            value.split(None, 1)[0].split("=", 1)[0].strip().casefold() == "allow-from"
            for value in xfo_values
            if value.split()
        )
        csp_values = header_values(context, "content-security-policy")
        parsed_csp = parse_csp(csp_values)
        ancestor_policies = parsed_csp.sources_for("frame-ancestors")
        restrictive_csp = any(
            sources and "*" not in tuple(source.casefold() for source in sources)
            for sources in ancestor_policies
        )
        protected_by: list[str] = []
        if xfo_valid:
            protected_by.append("x-frame-options")
        if restrictive_csp:
            protected_by.append("csp-frame-ancestors")
        if protected_by:
            status = FindingStatus.PASS
            severity = Severity.INFORMATIONAL
            summary = "An observable frame restriction is provided by at least one recognized mechanism; this does not assess application behavior."
        elif xfo_allow_from or (xfo_values and not xfo_valid):
            status = FindingStatus.WARN
            severity = self.default_severity
            summary = "X-Frame-Options was present but did not contain a reliably recognized protection value, and no restrictive CSP frame-ancestors policy was observed."
        else:
            status = FindingStatus.FAIL
            severity = self.default_severity
            summary = "Neither a recognized X-Frame-Options value nor a restrictive CSP frame-ancestors policy was observed."

        return (
            self.finding(
                context,
                status=status,
                severity=severity,
                summary=summary,
                evidence={
                    "x_frame_options_present": bool(xfo_values),
                    "x_frame_options_count": len(xfo_values),
                    "x_frame_options_recognized": xfo_values[0].upper() if xfo_valid else None,
                    "x_frame_options_allow_from_observed": xfo_allow_from,
                    "csp_frame_ancestors_present": bool(ancestor_policies),
                    "csp_frame_ancestors_policy_count": len(ancestor_policies),
                    "csp_frame_ancestors_restrictive_observed": restrictive_csp,
                    "protection_observed_via": tuple(protected_by),
                },
            ),
        )


class ServerInformationExposureCheck(BaseCheck):
    check_id = "exposure.server_headers"
    name = "Server information exposure"
    description = "Observes Server and X-Powered-By response headers without probing or banner grabbing."
    category = FindingCategory.EXPOSURE
    default_severity = Severity.INFORMATIONAL
    default_why_it_matters = "Software identifiers can help an observer target known versions, though disclosure alone is not a vulnerability."
    default_remediation = "Consider minimizing server and framework version details that are not needed in public responses."

    _VERSION = re.compile(r"(?<![A-Za-z0-9])v?\d+(?:\.\d+){1,}(?:[-+._][A-Za-z0-9.-]+)?")

    def run(self, context: ScanContext) -> tuple[Finding, ...]:
        unavailable = self.response_error(context)
        if unavailable is not None:
            return (unavailable,)
        server_values = tuple(value for value in header_values(context, "server") if value.strip())
        powered_values = tuple(value for value in header_values(context, "x-powered-by") if value.strip())
        values = server_values + powered_values
        versions = tuple(sorted({match for value in values for match in self._VERSION.findall(value)}))
        if not values:
            status = FindingStatus.PASS
            severity = Severity.INFORMATIONAL
            summary = "No Server or X-Powered-By information disclosure was observed in these response headers."
        else:
            status = FindingStatus.WARN
            severity = Severity.LOW if versions else Severity.INFORMATIONAL
            summary = (
                "Response headers disclose server or framework version details; this is informational and is not itself a vulnerability."
                if versions
                else "Response headers disclose a server or framework identifier; this is informational and is not itself a vulnerability."
            )
        return (
            self.finding(
                context,
                status=status,
                severity=severity,
                summary=summary,
                evidence={
                    "server_header_count": len(server_values),
                    "x_powered_by_header_count": len(powered_values),
                    "server_values": tuple(_safe_header_value(value) for value in server_values),
                    "x_powered_by_values": tuple(_safe_header_value(value) for value in powered_values),
                    "version_disclosed": bool(versions),
                    "version_tokens": versions,
                },
            ),
        )


def _scheme(url: str | None) -> str:
    if not url:
        return "unknown"
    try:
        scheme = urlsplit(url).scheme.casefold()
    except ValueError:
        return "unknown"
    return scheme if scheme in {"http", "https"} else "unknown"


def _safe_header_value(value: str) -> str:
    # These headers are intended to identify software. Bound and strip control
    # characters before preserving their observable evidence in a finding.
    return " ".join(value.replace("\r", " ").replace("\n", " ").split())[:160]
