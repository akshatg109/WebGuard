"""Aggregated review of already-normalized, value-free cookie metadata."""

from __future__ import annotations

import re

from app.scanner.checks.base import BaseCheck
from app.scanner.findings import Finding, FindingCategory, FindingStatus, Severity
from app.scanner.models import ObservedCookie, ScanContext

_SENSITIVE_NAME_HINT = re.compile(r"session|sessid|sid|auth|token|jwt|access|refresh", re.IGNORECASE)


class CookieSecurityCheck(BaseCheck):
    check_id = "cookies.security_attributes"
    name = "Cookie security attributes"
    description = "Aggregates normalized Set-Cookie attributes without retaining or returning cookie values."
    category = FindingCategory.COOKIES
    default_severity = Severity.LOW
    default_why_it_matters = "Cookie attributes affect transport confidentiality, script access, cross-site behavior, and scope; the right policy depends on each cookie's purpose."
    default_remediation = "Review each cookie's purpose and configure Secure, HttpOnly, SameSite, and scope attributes where appropriate."

    def run(self, context: ScanContext) -> tuple[Finding, ...]:
        unavailable = self.response_error(context)
        if unavailable is not None:
            return (unavailable,)

        cookies = context.response_cookies
        malformed_count = context.malformed_cookie_header_count
        header_count = context.set_cookie_header_count
        if header_count == 0:
            return (
                self.finding(
                    context,
                    status=FindingStatus.NOT_APPLICABLE,
                    severity=Severity.INFORMATIONAL,
                    summary="No Set-Cookie headers were observed in the captured response.",
                    why_it_matters="There were no observable response cookies to assess; cookies set through other mechanisms are not covered.",
                    evidence={
                        "cookie_count": 0,
                        "set_cookie_header_count": 0,
                        "cookie_values_stored": False,
                    },
                ),
            )

        https_response = _scheme(context.current_url) == "https"
        secure_missing_names = _names(cookies, lambda cookie: https_response and not cookie.secure)
        http_only_candidate_names = _names(
            cookies,
            lambda cookie: not cookie.http_only and bool(_SENSITIVE_NAME_HINT.search(cookie.name)),
        )
        same_site_missing_names = _names(cookies, lambda cookie: cookie.same_site is None)
        same_site_invalid_names = _names(cookies, lambda cookie: cookie.same_site == "invalid")
        same_site_none_without_secure = _names(
            cookies, lambda cookie: cookie.same_site == "none" and not cookie.secure
        )
        outside_domain_names = _names(cookies, lambda cookie: cookie.domain_scope in {"outside_target", "invalid_domain"})
        prefix_violation_names = _names(
            cookies,
            lambda cookie: cookie.prefix_requirements_satisfied is False,
        )
        invalid_attribute_names = _names(
            cookies,
            lambda cookie: cookie.path_scope == "invalid_path"
            or (cookie.max_age_present and not cookie.max_age_valid)
            or (cookie.expires_present and not cookie.expires_valid),
        )

        has_review_items = bool(
            malformed_count
            or secure_missing_names
            or http_only_candidate_names
            or same_site_missing_names
            or same_site_invalid_names
            or same_site_none_without_secure
            or outside_domain_names
            or prefix_violation_names
            or invalid_attribute_names
        )
        if secure_missing_names or same_site_none_without_secure:
            severity = Severity.MEDIUM
        elif has_review_items:
            severity = Severity.LOW
        else:
            severity = Severity.INFORMATIONAL

        summary = (
            "One or more cookie attributes merit review; these observations do not establish that a cookie is vulnerable."
            if has_review_items
            else "No issues detectable by these limited cookie attribute checks were observed."
        )
        evidence = {
            "cookie_count": len(cookies),
            "set_cookie_header_count": header_count,
            "malformed_set_cookie_header_count": malformed_count,
            "final_scheme": _scheme(context.current_url),
            "secure_check_applicable": https_response,
            "secure_missing_cookie_names": secure_missing_names,
            "http_only_missing_sensitive_name_candidates": http_only_candidate_names,
            "http_only_missing_count": sum(not cookie.http_only for cookie in cookies),
            "same_site_missing_cookie_names": same_site_missing_names,
            "same_site_invalid_cookie_names": same_site_invalid_names,
            "same_site_none_without_secure_cookie_names": same_site_none_without_secure,
            "domain_scope_outside_target_cookie_names": outside_domain_names,
            "prefix_requirement_violation_cookie_names": prefix_violation_names,
            "invalid_attribute_cookie_names": invalid_attribute_names,
            "cookie_values_stored": False,
            "cookie_observations": tuple(_cookie_evidence(cookie) for cookie in cookies),
        }
        return (
            self.finding(
                context,
                status=FindingStatus.WARN if has_review_items else FindingStatus.PASS,
                severity=severity,
                summary=summary,
                evidence=evidence,
            ),
        )


def _names(cookies: tuple[ObservedCookie, ...], predicate) -> tuple[str, ...]:
    return tuple(sorted({cookie.name for cookie in cookies if predicate(cookie)}))


def _cookie_evidence(cookie: ObservedCookie) -> dict[str, object]:
    return {
        "name": cookie.name,
        "secure": cookie.secure,
        "http_only": cookie.http_only,
        "same_site": cookie.same_site,
        "domain_scope": cookie.domain_scope,
        "path_scope": cookie.path_scope,
        "max_age_present": cookie.max_age_present,
        "max_age_valid": cookie.max_age_valid,
        "max_age_nonpositive": cookie.max_age_nonpositive,
        "expires_present": cookie.expires_present,
        "expires_valid": cookie.expires_valid,
        "prefix_kind": cookie.prefix_kind,
        "prefix_requirements_satisfied": cookie.prefix_requirements_satisfied,
    }


def _scheme(url: str | None) -> str:
    if not url:
        return "unknown"
    from urllib.parse import urlsplit

    try:
        return urlsplit(url).scheme.casefold()
    except ValueError:
        return "unknown"
