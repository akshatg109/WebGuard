"""Conservative passive technology signals from already-captured metadata/HTML."""

from __future__ import annotations

import re
from collections import defaultdict
from html.parser import HTMLParser
from urllib.parse import urlsplit

from app.scanner.checks.base import BaseCheck
from app.scanner.checks.headers import header_values
from app.scanner.findings import Finding, FindingCategory, FindingStatus, Severity
from app.scanner.models import ScanContext
from app.scanner.technologies import Technology, TechnologyCategory, TechnologyConfidence

MAX_TECH_HTML_BYTES = 256 * 1024
_RESOURCE_TAGS = frozenset(
    {"script", "img", "iframe", "frame", "source", "audio", "video", "track", "embed", "object", "input"}
)
_GENERATOR_PRODUCTS: tuple[tuple[re.Pattern[str], str, TechnologyCategory], ...] = (
    (re.compile(r"\bwordpress\b", re.I), "WordPress", TechnologyCategory.CMS),
    (re.compile(r"\bdrupal\b", re.I), "Drupal", TechnologyCategory.CMS),
    (re.compile(r"\bjoomla\b", re.I), "Joomla", TechnologyCategory.CMS),
    (re.compile(r"\bghost\b", re.I), "Ghost", TechnologyCategory.CMS),
    (re.compile(r"\bhugo\b", re.I), "Hugo", TechnologyCategory.FRAMEWORK),
    (re.compile(r"\bgatsby\b", re.I), "Gatsby", TechnologyCategory.FRAMEWORK),
    (re.compile(r"\bnext(?:\.js|js)\b", re.I), "Next.js", TechnologyCategory.FRAMEWORK),
    (re.compile(r"\bnuxt(?:\.js|js)?\b", re.I), "Nuxt", TechnologyCategory.FRAMEWORK),
)
_HEADER_PRODUCTS: tuple[tuple[re.Pattern[str], str, TechnologyCategory], ...] = (
    (re.compile(r"\bnginx\b", re.I), "nginx", TechnologyCategory.WEB_SERVER),
    (re.compile(r"\bapache\b", re.I), "Apache HTTP Server", TechnologyCategory.WEB_SERVER),
    (re.compile(r"\bcaddy\b", re.I), "Caddy", TechnologyCategory.WEB_SERVER),
    (re.compile(r"\bmicrosoft-iis\b", re.I), "Microsoft IIS", TechnologyCategory.WEB_SERVER),
    (re.compile(r"\blitespeed\b", re.I), "LiteSpeed", TechnologyCategory.WEB_SERVER),
    (re.compile(r"\bcloudflare\b", re.I), "Cloudflare", TechnologyCategory.PLATFORM),
)
_POWERED_PRODUCTS: tuple[tuple[re.Pattern[str], str, TechnologyCategory], ...] = (
    (re.compile(r"\bphp(?:/|\b)", re.I), "PHP", TechnologyCategory.RUNTIME),
    (re.compile(r"\basp\.net\b", re.I), "ASP.NET", TechnologyCategory.FRAMEWORK),
    (re.compile(r"\bexpress(?:\.js)?\b", re.I), "Express", TechnologyCategory.FRAMEWORK),
    (re.compile(r"\bnext\.js\b", re.I), "Next.js", TechnologyCategory.FRAMEWORK),
    (re.compile(r"\bnuxt(?:\.js)?\b", re.I), "Nuxt", TechnologyCategory.FRAMEWORK),
    (re.compile(r"\bdjango\b", re.I), "Django", TechnologyCategory.FRAMEWORK),
    (re.compile(r"\brails\b", re.I), "Ruby on Rails", TechnologyCategory.FRAMEWORK),
    (re.compile(r"\bspring\b", re.I), "Spring", TechnologyCategory.FRAMEWORK),
)


class _Collector:
    def __init__(self) -> None:
        self._signals: dict[tuple[str, TechnologyCategory], dict[str, TechnologyConfidence]] = defaultdict(dict)

    def add(
        self,
        name: str,
        category: TechnologyCategory,
        signal: str,
        confidence: TechnologyConfidence,
    ) -> None:
        signals = self._signals[(name, category)]
        previous = signals.get(signal)
        if previous is None or _confidence_rank(confidence) > _confidence_rank(previous):
            signals[signal] = confidence

    def technologies(self) -> tuple[Technology, ...]:
        results: list[Technology] = []
        ordered = sorted(self._signals.items(), key=lambda item: (item[0][0].casefold(), item[0][1].value))
        for (name, category), signals in ordered:
            highest = max(signals.values(), key=_confidence_rank)
            confidence = (
                TechnologyConfidence.HIGH
                if len(signals) >= 2 and highest is TechnologyConfidence.MEDIUM
                else highest
            )
            results.append(
                Technology(
                    name=name,
                    category=category,
                    confidence=confidence,
                    evidence=tuple(sorted(signals, key=str.casefold)),
                )
            )
        return tuple(results)


class _PassiveHtmlTechnologyParser(HTMLParser):
    def __init__(self, collector: _Collector) -> None:
        super().__init__(convert_charrefs=True)
        self.collector = collector

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        normalized_tag = tag.casefold()
        attributes: dict[str, str] = {}
        for name, value in attrs:
            if value is not None:
                attributes.setdefault(name.casefold(), value)

        if tag.casefold() == "meta" and attributes.get("name", "").casefold() == "generator":
            _add_generator_signal(attributes.get("content", ""), self.collector, "html_generator_metadata")

        if "ng-version" in attributes:
            self.collector.add("Angular", TechnologyCategory.FRAMEWORK, "html_marker:ng-version", TechnologyConfidence.MEDIUM)
        if "data-v-app" in attributes:
            self.collector.add("Vue", TechnologyCategory.FRAMEWORK, "html_marker:data-v-app", TechnologyConfidence.MEDIUM)
        if "data-reactroot" in attributes or "data-reactid" in attributes:
            marker = "data-reactroot" if "data-reactroot" in attributes else "data-reactid"
            self.collector.add("React", TechnologyCategory.LIBRARY, f"html_marker:{marker}", TechnologyConfidence.LOW)
        if attributes.get("id", "").casefold() == "__next_data__":
            self.collector.add("Next.js", TechnologyCategory.FRAMEWORK, "html_marker:__next_data__", TechnologyConfidence.MEDIUM)

        if normalized_tag in _RESOURCE_TAGS:
            value = attributes.get("src") or attributes.get("data")
            if value and (normalized_tag != "input" or attributes.get("type", "").casefold() == "image"):
                self._asset_path(value)
        if normalized_tag == "link":
            rels = frozenset(attributes.get("rel", "").casefold().split())
            if rels.intersection({"stylesheet", "icon", "apple-touch-icon", "preload", "modulepreload", "manifest"}):
                href = attributes.get("href")
                if href:
                    self._asset_path(href)

    def _asset_path(self, value: str) -> None:
        # This only inspects an attribute string; referenced resources are never requested.
        try:
            path = urlsplit(value).path.casefold()
        except ValueError:
            return
        path_signals = (
            ("/_next/static/", "Next.js", TechnologyCategory.FRAMEWORK, "html_asset_path:next_static"),
            ("/_nuxt/", "Nuxt", TechnologyCategory.FRAMEWORK, "html_asset_path:nuxt"),
            ("/wp-content/", "WordPress", TechnologyCategory.CMS, "html_asset_path:wp_content"),
            ("/wp-includes/", "WordPress", TechnologyCategory.CMS, "html_asset_path:wp_includes"),
            ("/sites/default/files/", "Drupal", TechnologyCategory.CMS, "html_asset_path:drupal_files"),
            ("/media/system/js/", "Joomla", TechnologyCategory.CMS, "html_asset_path:joomla_media"),
        )
        for needle, name, category, signal in path_signals:
            if needle in path:
                self.collector.add(name, category, signal, TechnologyConfidence.MEDIUM)


class TechnologyDetector:
    """Recognize a small allowlist of passive signals; never probes endpoints."""

    def detect(self, context: ScanContext) -> tuple[Technology, ...]:
        collector = _Collector()
        if context.http_status is None:
            return ()
        self._detect_headers(context, collector)
        if self._is_html(context) and context.response_body is not None and context.response_body_complete:
            body = context.response_body[:MAX_TECH_HTML_BYTES]
            parser = _PassiveHtmlTechnologyParser(collector)
            try:
                parser.feed(body.decode("utf-8", errors="replace"))
                parser.close()
            except Exception:
                # Keep already-collected response-header signals if HTML is malformed.
                pass
        return collector.technologies()

    @staticmethod
    def _is_html(context: ScanContext) -> bool:
        values = header_values(context, "content-type")
        media_types = {value.split(";", 1)[0].strip().casefold() for value in values}
        return len(media_types) == 1 and bool(media_types.intersection({"text/html", "application/xhtml+xml"}))

    def _detect_headers(self, context: ScanContext, collector: _Collector) -> None:
        for value in header_values(context, "server"):
            for pattern, name, category in _HEADER_PRODUCTS:
                if pattern.search(value):
                    collector.add(name, category, f"server_header:{name.casefold()}", TechnologyConfidence.MEDIUM)
        for value in header_values(context, "x-powered-by"):
            for pattern, name, category in _POWERED_PRODUCTS:
                if pattern.search(value):
                    collector.add(name, category, f"x_powered_by:{name.casefold()}", TechnologyConfidence.MEDIUM)
        for value in header_values(context, "x-generator"):
            _add_generator_signal(value, collector, "x_generator_header")
        if header_values(context, "x-vercel-id"):
            collector.add("Vercel", TechnologyCategory.PLATFORM, "header:x-vercel-id", TechnologyConfidence.MEDIUM)
        if header_values(context, "x-nextjs-cache"):
            collector.add("Next.js", TechnologyCategory.FRAMEWORK, "header:x-nextjs-cache", TechnologyConfidence.MEDIUM)
        if header_values(context, "x-drupal-cache"):
            collector.add("Drupal", TechnologyCategory.CMS, "header:x-drupal-cache", TechnologyConfidence.MEDIUM)


class TechnologyDetectionCheck(BaseCheck):
    check_id = "technology.passive_indicators"
    name = "Passive technology indicators"
    description = "Identifies a conservative allowlist of response-header and HTML markers already in ScanContext."
    category = FindingCategory.TECHNOLOGY
    default_severity = Severity.INFORMATIONAL
    default_why_it_matters = "Technology context may help interpret configuration findings, but it does not establish vulnerabilities or the full deployment stack."
    default_remediation = "No remediation is implied by a passive technology indicator."

    def __init__(self, detector: TechnologyDetector | None = None) -> None:
        self._detector = detector or TechnologyDetector()

    def run(self, context: ScanContext) -> tuple[Finding, ...]:
        unavailable = self.response_error(context)
        if unavailable is not None:
            return (unavailable,)
        technologies = self._detector.detect(context)
        return (
            self.finding(
                context,
                status=FindingStatus.PASS,
                severity=Severity.INFORMATIONAL,
                summary=(
                    f"Observed {len(technologies)} passive technology indicator(s); these signals are not active fingerprinting or verification."
                    if technologies
                    else "No recognized passive technology indicators were observed; this is not evidence that no technologies are present."
                ),
                evidence={
                    "technology_count": len(technologies),
                    "technology_names": tuple(technology.name for technology in technologies),
                    "active_probes_performed": False,
                },
                metadata={"technologies": tuple(technology.to_dict() for technology in technologies)},
            ),
        )


def _add_generator_signal(value: str, collector: _Collector, source: str) -> None:
    for pattern, name, category in _GENERATOR_PRODUCTS:
        if pattern.search(value):
            collector.add(name, category, f"{source}:{name.casefold()}", TechnologyConfidence.MEDIUM)


def _confidence_rank(confidence: TechnologyConfidence) -> int:
    return {
        TechnologyConfidence.LOW: 0,
        TechnologyConfidence.MEDIUM: 1,
        TechnologyConfidence.HIGH: 2,
    }[confidence]
