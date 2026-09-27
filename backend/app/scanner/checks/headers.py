"""Case-insensitive, duplicate-preserving response header parsing helpers."""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from app.scanner.models import HeaderPairs, ScanContext

_DIRECTIVE_NAME = re.compile(r"^[a-z][a-z0-9-]*$")
_REFERRER_POLICY_VALUES = frozenset(
    {
        "no-referrer",
        "no-referrer-when-downgrade",
        "same-origin",
        "origin",
        "strict-origin",
        "origin-when-cross-origin",
        "strict-origin-when-cross-origin",
        "unsafe-url",
    }
)


def header_values(context: ScanContext, name: str) -> tuple[str, ...]:
    """Return matching values in wire order without collapsing duplicate headers."""
    normalized = name.strip().casefold()
    return tuple(
        value.strip()
        for header_name, value in context.response_headers
        if header_name.strip().casefold() == normalized
    )


@dataclass(frozen=True, slots=True)
class ParsedCsp:
    policies: tuple[tuple[tuple[str, tuple[str, ...]], ...], ...]
    malformed_policy_indexes: tuple[int, ...]
    duplicate_directives: tuple[str, ...]

    @property
    def flattened_directives(self) -> tuple[tuple[str, tuple[str, ...]], ...]:
        return tuple(directive for policy in self.policies for directive in policy)

    @property
    def directive_names(self) -> tuple[str, ...]:
        return tuple(sorted({name for name, _sources in self.flattened_directives}))

    @property
    def unsafe_inline(self) -> bool:
        return any(
            source.casefold() == "'unsafe-inline'"
            for _name, sources in self.flattened_directives
            for source in sources
        )

    @property
    def unsafe_eval(self) -> bool:
        return any(
            source.casefold() == "'unsafe-eval'"
            for _name, sources in self.flattened_directives
            for source in sources
        )

    @property
    def broad_sources(self) -> tuple[str, ...]:
        broad = {
            "subdomain_wildcard" if source.startswith("*.") else source.casefold()
            for _name, sources in self.flattened_directives
            for source in sources
            if source == "*" or source.casefold() in {"http:", "https:"} or source.startswith("*.")
        }
        return tuple(sorted(broad, key=str.casefold))

    def sources_for(self, directive_name: str) -> tuple[tuple[str, ...], ...]:
        wanted = directive_name.casefold()
        return tuple(
            sources
            for policy in self.policies
            for name, sources in policy
            if name == wanted
        )


def parse_csp(values: tuple[str, ...]) -> ParsedCsp:
    """Parse directive structure conservatively; do not claim full CSP safety."""
    policies: list[tuple[tuple[str, tuple[str, ...]], ...]] = []
    malformed: list[int] = []
    duplicates: set[str] = set()

    for policy_index, raw_policy in enumerate(values):
        if not raw_policy.strip():
            malformed.append(policy_index)
            policies.append(())
            continue
        parsed: list[tuple[str, tuple[str, ...]]] = []
        seen: set[str] = set()
        invalid = False
        for raw_directive in raw_policy.split(";"):
            directive = raw_directive.strip()
            if not directive:
                continue
            pieces = directive.split()
            name = pieces[0].casefold()
            if not _DIRECTIVE_NAME.fullmatch(name):
                invalid = True
                continue
            if name in seen:
                duplicates.add(name)
                # CSP uses the first occurrence of a directive in a policy.
                continue
            seen.add(name)
            sources = tuple(pieces[1:])
            if any(source.startswith("'") != source.endswith("'") for source in sources):
                invalid = True
            parsed.append((name, sources))
        if not parsed:
            invalid = True
        if invalid:
            malformed.append(policy_index)
        policies.append(tuple(parsed))

    return ParsedCsp(
        policies=tuple(policies),
        malformed_policy_indexes=tuple(malformed),
        duplicate_directives=tuple(sorted(duplicates)),
    )


def parse_permissions_policy(values: tuple[str, ...]) -> tuple[tuple[str, ...], bool, tuple[str, ...]]:
    """Parse directive/parenthesis structure without judging app-specific policy."""
    directives: list[str] = []
    seen: set[str] = set()
    errors: list[str] = []
    combined = ",".join(values)
    segments, balanced = _split_commas_outside_parentheses(combined)
    if not balanced:
        errors.append("unbalanced_parentheses")

    for segment in segments:
        part = segment.strip()
        if not part:
            errors.append("empty_directive")
            continue
        if "=" not in part:
            errors.append("missing_equals")
            continue
        name, allowlist = (item.strip() for item in part.split("=", 1))
        normalized_name = name.casefold()
        if not _DIRECTIVE_NAME.fullmatch(normalized_name):
            errors.append("invalid_feature_name")
            continue
        if len(allowlist) < 2 or not allowlist.startswith("(") or not allowlist.endswith(")"):
            errors.append("invalid_allowlist")
            continue
        if "(" in allowlist[1:-1] or ")" in allowlist[1:-1]:
            errors.append("nested_parentheses")
            continue
        if any(not _valid_permissions_item(token) for token in allowlist[1:-1].split()):
            errors.append("invalid_allowlist_item")
            continue
        if normalized_name in seen:
            errors.append("duplicate_feature")
            continue
        seen.add(normalized_name)
        directives.append(normalized_name)

    return tuple(directives), bool(errors), tuple(sorted(set(errors)))


def _valid_permissions_item(token: str) -> bool:
    if token.casefold() in {"*", "self", "src", "'self'", "'src'"}:
        return True
    origin = token
    if len(origin) >= 2 and origin[0] == origin[-1] and origin[0] in {"'", '"'}:
        origin = origin[1:-1]
    elif origin.startswith(("'", '"')) or origin.endswith(("'", '"')):
        return False
    try:
        parts = urlsplit(origin)
        return (
            parts.scheme in {"http", "https"}
            and bool(parts.hostname)
            and parts.port != 0
            and parts.username is None
            and parts.password is None
            and parts.path in {"", "/"}
            and not parts.query
            and not parts.fragment
        )
    except ValueError:
        return False


def _split_commas_outside_parentheses(value: str) -> tuple[list[str], bool]:
    parts: list[str] = []
    start = 0
    depth = 0
    balanced = True
    for index, character in enumerate(value):
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth < 0:
                balanced = False
                depth = 0
        elif character == "," and depth == 0:
            parts.append(value[start:index])
            start = index + 1
    if depth != 0:
        balanced = False
    parts.append(value[start:])
    return parts, balanced


def recognized_referrer_policies(values: tuple[str, ...]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Recognize comma-list fallbacks and preserve wire/value order."""
    tokens = tuple(token.strip().casefold() for value in values for token in value.split(","))
    recognized = tuple(token for token in tokens if token in _REFERRER_POLICY_VALUES)
    unknown = tuple(token for token in tokens if token and token not in _REFERRER_POLICY_VALUES)
    return recognized, unknown


@dataclass(frozen=True, slots=True)
class ParsedHsts:
    max_age: int | None
    include_subdomains: bool
    preload: bool
    errors: tuple[str, ...]


def parse_hsts(values: tuple[str, ...]) -> ParsedHsts:
    """Parse the observable HSTS directives without inferring preload eligibility."""
    errors: set[str] = set()
    if len(values) != 1:
        errors.add("duplicate_header" if values else "missing_header")
    max_age: int | None = None
    include_subdomains = False
    preload = False
    seen: set[str] = set()

    for value in values:
        for raw_directive in value.split(";"):
            directive = raw_directive.strip()
            if not directive:
                continue
            name, separator, argument = directive.partition("=")
            normalized_name = name.strip().casefold()
            normalized_argument = argument.strip()
            if normalized_name in seen:
                errors.add(f"duplicate_{normalized_name.replace('-', '_')}")
                continue
            seen.add(normalized_name)
            if normalized_name == "max-age":
                if not separator or not normalized_argument.isdecimal():
                    errors.add("invalid_max_age")
                else:
                    try:
                        max_age = int(normalized_argument, 10)
                    except ValueError:
                        errors.add("invalid_max_age")
            elif normalized_name == "includesubdomains":
                if separator:
                    errors.add("invalid_include_subdomains")
                else:
                    include_subdomains = True
            elif normalized_name == "preload":
                if separator:
                    errors.add("invalid_preload")
                else:
                    preload = True

    if max_age is None:
        errors.add("max_age_missing")
    return ParsedHsts(
        max_age=max_age,
        include_subdomains=include_subdomains,
        preload=preload,
        errors=tuple(sorted(errors)),
    )
