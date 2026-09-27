"""Bounded passive HTML inspection for obvious HTTP mixed-content references."""

from __future__ import annotations

from collections import Counter
from html.parser import HTMLParser
import ipaddress
from urllib.parse import urlsplit

import idna

from app.scanner.checks.base import BaseCheck
from app.scanner.checks.headers import header_values
from app.scanner.findings import Finding, FindingCategory, FindingStatus, Severity
from app.scanner.models import ScanContext

MAX_HTML_INSPECTION_BYTES = 256 * 1024
MAX_REFERENCES_SCANNED = 512
MAX_REFERENCE_ORIGINS_REPORTED = 16

_STATIC_RESOURCE_TAGS = {
    ("script", "src"): "script",
    ("img", "src"): "image",
    ("iframe", "src"): "iframe",
    ("frame", "src"): "frame",
    ("source", "src"): "media",
    ("audio", "src"): "media",
    ("video", "src"): "media",
    ("track", "src"): "media",
    ("embed", "src"): "embed",
    ("object", "data"): "object",
    ("video", "poster"): "image",
}
_ACTIVE_RESOURCE_TYPES = frozenset({"script", "stylesheet", "iframe", "frame", "embed", "object"})


class MixedContentCheck(BaseCheck):
    check_id = "content.mixed_http_resources"
    name = "Mixed-content references"
    description = "Inspects a bounded portion of captured HTML for absolute HTTP resource attributes; it never fetches them."
    category = FindingCategory.CONTENT
    default_severity = Severity.LOW
    default_why_it_matters = "HTTP resources referenced by an HTTPS document do not receive the same transport protection as the document."
    default_remediation = "Where appropriate, update resource references to HTTPS and verify the resource is available securely."

    def run(self, context: ScanContext) -> tuple[Finding, ...]:
        unavailable = self.response_error(context)
        if unavailable is not None:
            return (unavailable,)

        final_scheme = _scheme(context.current_url)
        if final_scheme != "https":
            return (
                self.finding(
                    context,
                    status=FindingStatus.NOT_APPLICABLE,
                    severity=Severity.INFORMATIONAL,
                    summary="Mixed content is evaluated only for an HTTPS HTML document.",
                    evidence={"final_scheme": final_scheme, "body_inspected": False},
                ),
            )

        content_types = header_values(context, "content-type")
        mime_types = tuple(value.split(";", 1)[0].strip().casefold() for value in content_types)
        if len(set(mime_types)) != 1 or not mime_types or mime_types[0] not in {"text/html", "application/xhtml+xml"}:
            return (
                self.finding(
                    context,
                    status=FindingStatus.NOT_APPLICABLE,
                    severity=Severity.INFORMATIONAL,
                    summary="The captured response was not unambiguously identified as HTML; no body inspection was performed.",
                    evidence={"content_types": mime_types, "body_inspected": False},
                ),
            )
        if context.response_body is None or not context.response_body_complete:
            return (
                self.finding(
                    context,
                    status=FindingStatus.NOT_APPLICABLE,
                    severity=Severity.INFORMATIONAL,
                    summary="A complete HTML response body is not available in ScanContext; no fetch was attempted.",
                    evidence={
                        "body_available": context.response_body is not None,
                        "body_complete": context.response_body_complete,
                        "body_inspected": False,
                        "subresources_fetched": False,
                    },
                ),
            )

        body = context.response_body[:MAX_HTML_INSPECTION_BYTES]
        body_truncated = len(context.response_body) > len(body)
        parser = _ResourceReferenceParser()
        try:
            parser.feed(body.decode("utf-8", errors="replace"))
            parser.close()
        except Exception:
            return (
                self.finding(
                    context,
                    status=FindingStatus.ERROR,
                    severity=Severity.INFORMATIONAL,
                    summary="The captured HTML could not be inspected; no security conclusion was made.",
                    evidence={"body_inspected": False, "subresources_fetched": False},
                ),
            )

        evidence: dict[str, object] = {
            "content_type": mime_types[0],
            "body_inspected": True,
            "body_bytes_inspected": len(body),
            "body_analysis_truncated": body_truncated,
            "reference_scan_truncated": parser.reference_scan_truncated,
            "detected_reference_count": parser.reference_count,
            "resource_type_counts": tuple(sorted(parser.resource_counts.items())),
            "sanitized_reference_origins": tuple(sorted(parser.reference_origins)),
            "additional_origins_omitted": parser.omitted_origin_count,
            "subresources_fetched": False,
        }
        if parser.reference_count:
            active = any(name in _ACTIVE_RESOURCE_TYPES for name in parser.resource_counts)
            return (
                self.finding(
                    context,
                    status=FindingStatus.WARN,
                    severity=Severity.HIGH if active else Severity.LOW,
                    summary=(
                        f"The HTTPS HTML response references {parser.reference_count} absolute HTTP resource(s); none were fetched."
                    ),
                    why_it_matters=(
                        "HTTP scripts, styles, frames, and embeds can be modified independently of the HTTPS document."
                        if active
                        else "HTTP images and media can be modified independently of the HTTPS document, although their impact is context-dependent."
                    ),
                    evidence=evidence,
                ),
            )

        if body_truncated or parser.reference_scan_truncated:
            return (
                self.finding(
                    context,
                    status=FindingStatus.WARN,
                    severity=Severity.INFORMATIONAL,
                    summary="No obvious HTTP resource references were found in the inspected HTML portion; the whole document was not inspected.",
                    evidence=evidence,
                ),
            )
        return (
            self.finding(
                context,
                status=FindingStatus.PASS,
                severity=Severity.INFORMATIONAL,
                summary="No obvious absolute HTTP resource references were found in the inspected HTML attributes.",
                evidence=evidence,
            ),
        )


class _ResourceReferenceParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.reference_count = 0
        self.resource_counts: Counter[str] = Counter()
        self.reference_origins: set[str] = set()
        self.omitted_origin_count = 0
        self.reference_scan_truncated = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if self.reference_count >= MAX_REFERENCES_SCANNED:
            self.reference_scan_truncated = True
            return
        attributes: dict[str, str] = {}
        for name, value in attrs:
            if value is not None:
                attributes.setdefault(name.casefold(), value)
        normalized_tag = tag.casefold()

        for (candidate_tag, attribute), resource_type in _STATIC_RESOURCE_TAGS.items():
            if candidate_tag == normalized_tag and attribute in attributes:
                self._record(attributes[attribute], resource_type)

        if normalized_tag == "input" and attributes.get("type", "").casefold() == "image":
            if "src" in attributes:
                self._record(attributes["src"], "image")

        if normalized_tag == "link" and "href" in attributes:
            resource_type = _link_resource_type(attributes)
            if resource_type is not None:
                self._record(attributes["href"], resource_type)

    def _record(self, raw_url: str, resource_type: str) -> None:
        origin = _http_origin(raw_url)
        if origin is None:
            return
        if self.reference_count >= MAX_REFERENCES_SCANNED:
            self.reference_scan_truncated = True
            return
        self.reference_count += 1
        self.resource_counts[resource_type] += 1
        if origin in self.reference_origins:
            return
        if len(self.reference_origins) < MAX_REFERENCE_ORIGINS_REPORTED:
            self.reference_origins.add(origin)
        else:
            self.omitted_origin_count += 1


def _link_resource_type(attributes: dict[str, str]) -> str | None:
    rels = frozenset(attributes.get("rel", "").casefold().split())
    if "stylesheet" in rels:
        return "stylesheet"
    if "modulepreload" in rels:
        return "script"
    if "preload" in rels:
        as_value = attributes.get("as", "").casefold()
        return {"script": "script", "style": "stylesheet", "image": "image", "font": "font", "audio": "media", "video": "media"}.get(as_value, "preload")
    if rels.intersection({"icon", "apple-touch-icon"}):
        return "icon"
    if "manifest" in rels:
        return "manifest"
    if "preconnect" in rels:
        return "connection_hint"
    return None


def _http_origin(raw_url: str) -> str | None:
    try:
        parts = urlsplit(raw_url.strip())
        if parts.scheme.casefold() != "http" or not parts.hostname:
            return None
        try:
            address = ipaddress.ip_address(parts.hostname)
            hostname = address.compressed.lower()
        except ValueError:
            hostname = idna.encode(parts.hostname, uts46=True, std3_rules=True).decode("ascii").casefold()
        port = parts.port
    except (ValueError, UnicodeError, idna.IDNAError):
        return None
    authority_host = f"[{hostname}]" if ":" in hostname else hostname
    authority = authority_host if port in (None, 80) else f"{authority_host}:{port}"
    return f"http://{authority}"


def _scheme(url: str | None) -> str:
    if not url:
        return "unknown"
    try:
        return urlsplit(url).scheme.casefold()
    except ValueError:
        return "unknown"
