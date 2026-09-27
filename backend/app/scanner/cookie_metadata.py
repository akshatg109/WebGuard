"""Normalize Set-Cookie attributes while discarding values immediately."""

from __future__ import annotations

import re
from collections.abc import Sequence
from email.utils import parsedate_to_datetime
from http.cookies import CookieError, Morsel, SimpleCookie
from urllib.parse import urlsplit

import idna

from app.scanner.models import ObservedCookie

_INTEGER = re.compile(r"^-?[0-9]+$")


def parse_set_cookie_headers(
    values: Sequence[str],
    *,
    target_url: str,
) -> tuple[tuple[ObservedCookie, ...], int]:
    """Parse each Set-Cookie field independently, retaining attributes but never values.

    A comma-joined field producing multiple cookies is considered ambiguous and
    skipped: a comma can also be part of Expires, so guessing boundaries is unsafe.
    """
    target_host = _target_host(target_url)
    cookies: list[ObservedCookie] = []
    malformed_count = 0
    for raw_header in values:
        parsed = SimpleCookie()
        try:
            parsed.load(raw_header)
        except CookieError:
            malformed_count += 1
            continue
        morsels = tuple(parsed.values())
        if len(morsels) != 1:
            malformed_count += 1
            continue
        cookie = _normalize_morsel(morsels[0], target_host)
        if cookie is None:
            malformed_count += 1
            continue
        cookies.append(cookie)
    return tuple(cookies), malformed_count


def _normalize_morsel(morsel: Morsel[str], target_host: str | None) -> ObservedCookie | None:
    # Do not read or copy morsel.value. Only the cookie name and attributes survive.
    name = morsel.key
    if not name:
        return None

    secure = bool(morsel["secure"])
    http_only = bool(morsel["httponly"])
    raw_same_site = morsel["samesite"].strip().casefold()
    same_site = raw_same_site if raw_same_site in {"strict", "lax", "none"} else ("invalid" if raw_same_site else None)

    raw_domain = morsel["domain"].strip()
    domain_scope = _domain_scope(raw_domain, target_host)
    path_scope = _path_scope(morsel["path"])

    raw_max_age = morsel["max-age"].strip()
    max_age_present = bool(raw_max_age)
    max_age_valid = bool(_INTEGER.fullmatch(raw_max_age))
    max_age_nonpositive = False
    if max_age_valid:
        try:
            max_age_nonpositive = int(raw_max_age, 10) <= 0
        except ValueError:
            max_age_valid = False

    raw_expires = morsel["expires"].strip()
    expires_present = bool(raw_expires)
    expires_valid = _valid_expiry(raw_expires) if expires_present else False

    prefix_kind: str | None = None
    prefix_satisfied: bool | None = None
    if name.startswith("__Host-"):
        prefix_kind = "host"
        prefix_satisfied = secure and not raw_domain and morsel["path"] == "/"
    elif name.startswith("__Secure-"):
        prefix_kind = "secure"
        prefix_satisfied = secure

    return ObservedCookie(
        name=name,
        secure=secure,
        http_only=http_only,
        same_site=same_site,
        domain_scope=domain_scope,
        path_scope=path_scope,
        max_age_present=max_age_present,
        max_age_valid=max_age_valid if max_age_present else False,
        max_age_nonpositive=max_age_nonpositive,
        expires_present=expires_present,
        expires_valid=expires_valid,
        prefix_kind=prefix_kind,
        prefix_requirements_satisfied=prefix_satisfied,
    )


def _domain_scope(raw_domain: str, target_host: str | None) -> str:
    domain = raw_domain.strip().lstrip(".").rstrip(".").casefold()
    if not domain:
        return "host_only"
    if not target_host:
        return "unknown_target"
    try:
        normalized_domain = idna.encode(domain, uts46=True, std3_rules=True).decode("ascii").casefold()
    except (idna.IDNAError, UnicodeError):
        return "invalid_domain"
    normalized_host = target_host.casefold().rstrip(".")
    if normalized_host == normalized_domain:
        return "target_and_subdomains"
    if normalized_host.endswith(f".{normalized_domain}"):
        return "parent_domain"
    return "outside_target"


def _path_scope(raw_path: str) -> str:
    path = raw_path.strip()
    if not path:
        return "default_path"
    if not path.startswith("/"):
        return "invalid_path"
    return "root" if path == "/" else "scoped_path"


def _valid_expiry(value: str) -> bool:
    try:
        return parsedate_to_datetime(value) is not None
    except (TypeError, ValueError, OverflowError):
        return False


def _target_host(url: str) -> str | None:
    try:
        return urlsplit(url).hostname
    except ValueError:
        return None
