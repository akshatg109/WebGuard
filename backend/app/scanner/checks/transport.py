"""Transport observations from the final validated request and redirect chain."""

from __future__ import annotations

from urllib.parse import urlsplit

from app.scanner.checks.base import BaseCheck
from app.scanner.findings import Finding, FindingCategory, FindingStatus, Severity
from app.scanner.models import ScanContext


class HttpsAvailabilityCheck(BaseCheck):
    check_id = "transport.https"
    name = "HTTPS availability"
    description = "Observes whether the final response URL uses HTTPS."
    category = FindingCategory.TRANSPORT
    default_severity = Severity.HIGH
    default_why_it_matters = "HTTPS protects requests in transit and helps prevent passive observation or network tampering."
    default_remediation = "Serve the site over HTTPS with a valid TLS certificate."

    def run(self, context: ScanContext) -> tuple[Finding, ...]:
        unavailable = self.response_error(context)
        if unavailable is not None:
            return (unavailable,)

        requested_scheme = _scheme(context.normalized_url)
        final_scheme = _scheme(context.current_url)
        if final_scheme == "https":
            finding = self.finding(
                context,
                status=FindingStatus.PASS,
                severity=Severity.INFORMATIONAL,
                summary="The final response was received over HTTPS; this alone does not establish that the application is secure.",
                evidence={
                    "requested_scheme": requested_scheme,
                    "final_scheme": final_scheme,
                    "https_observed": True,
                },
            )
        else:
            finding = self.finding(
                context,
                status=FindingStatus.FAIL,
                severity=self.default_severity,
                summary="The final response URL uses HTTP, so this request was not protected by TLS.",
                evidence={
                    "requested_scheme": requested_scheme,
                    "final_scheme": final_scheme,
                    "https_observed": False,
                },
            )
        return (finding,)


class HttpToHttpsRedirectCheck(BaseCheck):
    check_id = "transport.http_to_https_redirect"
    name = "HTTP-to-HTTPS redirect"
    description = "Checks the recorded redirect chain for an HTTP-to-HTTPS upgrade."
    category = FindingCategory.TRANSPORT
    default_severity = Severity.MEDIUM
    default_why_it_matters = "An HTTP entry point can expose the initial request before the browser reaches a secure origin."
    default_remediation = "Redirect HTTP requests to the canonical HTTPS origin."

    def run(self, context: ScanContext) -> tuple[Finding, ...]:
        unavailable = self.response_error(context)
        if unavailable is not None:
            return (unavailable,)

        requested_scheme = _scheme(context.normalized_url)
        final_scheme = _scheme(context.current_url)
        if requested_scheme != "http":
            return (
                self.finding(
                    context,
                    status=FindingStatus.NOT_APPLICABLE,
                    severity=Severity.INFORMATIONAL,
                    summary="The requested URL already used HTTPS, so an HTTP upgrade redirect was not applicable.",
                    evidence={"requested_scheme": requested_scheme, "redirect_count": len(context.redirect_chain)},
                ),
            )

        destination_schemes = tuple(
            _scheme(hop.destination_url) for hop in context.redirect_chain
        )
        upgraded = "https" in destination_schemes and final_scheme == "https"
        return (
            self.finding(
                context,
                status=FindingStatus.PASS if upgraded else FindingStatus.FAIL,
                severity=Severity.INFORMATIONAL if upgraded else self.default_severity,
                summary=(
                    "The recorded HTTP request redirected to HTTPS and ended on HTTPS."
                    if upgraded
                    else "No complete HTTP-to-HTTPS upgrade was observed in the recorded redirect chain."
                ),
                evidence={
                    "requested_scheme": requested_scheme,
                    "redirect_count": len(context.redirect_chain),
                    "redirect_destination_schemes": destination_schemes,
                    "final_scheme": final_scheme,
                    "https_upgrade_observed": upgraded,
                },
            ),
        )


class FinalUrlSchemeCheck(BaseCheck):
    check_id = "transport.final_scheme"
    name = "Final URL scheme"
    description = "Records the scheme of the final validated response URL."
    category = FindingCategory.TRANSPORT
    default_severity = Severity.INFORMATIONAL
    default_why_it_matters = "The final scheme describes transport for this response but does not assess application-level security."
    default_remediation = "Review the final destination scheme when interpreting transport-related checks."

    def run(self, context: ScanContext) -> tuple[Finding, ...]:
        unavailable = self.response_error(context)
        if unavailable is not None:
            return (unavailable,)
        scheme = _scheme(context.current_url)
        https = scheme == "https"
        return (
            self.finding(
                context,
                status=FindingStatus.PASS if https else FindingStatus.WARN,
                severity=Severity.INFORMATIONAL,
                summary=(
                    "The final validated response URL uses HTTPS."
                    if https
                    else "The final validated response URL uses HTTP; the transport check records this without treating it as a score."
                ),
                evidence={
                    "requested_scheme": _scheme(context.normalized_url),
                    "final_scheme": scheme,
                    "redirect_count": len(context.redirect_chain),
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
