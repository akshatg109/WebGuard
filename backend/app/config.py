"""Backend-only Supabase and scan API configuration."""

from dataclasses import dataclass
import ipaddress
from os import environ
from urllib.parse import urlsplit

_MIN_SCANNER_API_TOKEN_LENGTH = 32


@dataclass(frozen=True)
class SupabaseSettings:
    url: str | None
    publishable_key: str | None
    secret_key: str | None

    @classmethod
    def from_environment(cls) -> "SupabaseSettings":
        url = environ.get("SUPABASE_URL")
        if url:
            parsed = urlsplit(url)
            if parsed.scheme != "https" and parsed.hostname not in {
                "localhost",
                "127.0.0.1",
            }:
                raise ValueError("SUPABASE_URL must use HTTPS outside local development.")
            if not parsed.hostname or parsed.username or parsed.password:
                raise ValueError("SUPABASE_URL must be a valid URL without credentials.")

        return cls(
            url=url,
            publishable_key=environ.get("SUPABASE_PUBLISHABLE_KEY"),
            secret_key=environ.get("SUPABASE_SECRET_KEY"),
        )

    def require_configured(self) -> tuple[str, str, str]:
        """Require credentials before creating a privileged server-side client."""
        missing = [
            name
            for name, value in (
                ("SUPABASE_URL", self.url),
                ("SUPABASE_PUBLISHABLE_KEY", self.publishable_key),
                ("SUPABASE_SECRET_KEY", self.secret_key),
            )
            if not value
        ]
        if missing:
            raise RuntimeError(
                "Missing server-only Supabase configuration: " + ", ".join(missing)
            )
        assert self.url is not None
        assert self.publishable_key is not None
        assert self.secret_key is not None
        return self.url, self.publishable_key, self.secret_key


@dataclass(frozen=True, slots=True)
class ScanRateLimitSettings:
    """Per-process scan creation budget for the synchronous MVP API."""

    max_requests: int = 5
    window_seconds: int = 60

    def __post_init__(self) -> None:
        if not 1 <= self.max_requests <= 10_000:
            raise ValueError("SCAN_RATE_LIMIT_MAX_REQUESTS must be between 1 and 10000.")
        if not 1 <= self.window_seconds <= 86_400:
            raise ValueError("SCAN_RATE_LIMIT_WINDOW_SECONDS must be between 1 and 86400.")

    @classmethod
    def from_environment(cls) -> "ScanRateLimitSettings":
        try:
            max_requests = int(environ.get("SCAN_RATE_LIMIT_MAX_REQUESTS", "5"))
            window_seconds = int(environ.get("SCAN_RATE_LIMIT_WINDOW_SECONDS", "60"))
        except ValueError as exc:
            raise ValueError("Scan rate-limit settings must be integers.") from exc
        return cls(max_requests=max_requests, window_seconds=window_seconds)


@dataclass(frozen=True, slots=True)
class AiRateLimitSettings:
    """Process-local per-user budget for explicitly requested AI generations."""

    max_requests: int = 10
    window_seconds: int = 3_600

    def __post_init__(self) -> None:
        if not 1 <= self.max_requests <= 1_000:
            raise ValueError("AI_RATE_LIMIT_MAX_REQUESTS must be between 1 and 1000.")
        if not 1 <= self.window_seconds <= 86_400:
            raise ValueError("AI_RATE_LIMIT_WINDOW_SECONDS must be between 1 and 86400.")

    @classmethod
    def from_environment(cls) -> "AiRateLimitSettings":
        try:
            max_requests = int(environ.get("AI_RATE_LIMIT_MAX_REQUESTS", "10"))
            window_seconds = int(environ.get("AI_RATE_LIMIT_WINDOW_SECONDS", "3600"))
        except ValueError as exc:
            raise ValueError("AI rate-limit settings must be integers.") from exc
        return cls(max_requests=max_requests, window_seconds=window_seconds)


@dataclass(frozen=True, slots=True)
class AiProviderSettings:
    """Server-only OpenAI-compatible provider configuration."""

    provider: str
    api_key: str
    model: str
    base_url: str
    timeout_seconds: float = 20.0

    @classmethod
    def from_environment(cls) -> "AiProviderSettings | None":
        """Return ``None`` for an absent or invalid optional configuration."""
        provider = environ.get("AI_PROVIDER", "").strip().casefold()
        api_key = environ.get("AI_API_KEY", "")
        model = environ.get("AI_MODEL", "").strip()
        if not provider or not api_key or not model:
            return None
        if (
            provider not in {"openai", "openrouter", "openai-compatible"}
            or api_key.strip() != api_key
            or not api_key.isascii()
            or any(ord(char) < 0x21 or ord(char) > 0x7E for char in api_key)
            or not 1 <= len(api_key) <= 4_096
            or not 1 <= len(model) <= 160
            or any(ord(char) < 0x20 or ord(char) == 0x7F for char in model)
        ):
            return None

        base_url = environ.get("AI_BASE_URL", "").strip()
        if not base_url:
            base_url = {
                "openai": "https://api.openai.com/v1",
                "openrouter": "https://openrouter.ai/api/v1",
            }.get(provider, "")
        if not _valid_ai_base_url(base_url):
            return None
        return cls(provider=provider, api_key=api_key, model=model, base_url=base_url.rstrip("/"))


def _valid_ai_base_url(value: str) -> bool:
    if (
        not value
        or len(value) > 2_048
        or value.strip() != value
        or any(ord(char) <= 0x20 or ord(char) == 0x7F for char in value)
    ):
        return False
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return False
    if (
        not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path.endswith("/../")
        or parsed.scheme not in {"https", "http"}
        or (port is not None and not 1 <= port <= 65_535)
    ):
        return False
    host = hostname.casefold().rstrip(".")
    if host == "localhost":
        return True
    if host.endswith((".localhost", ".local", ".internal")):
        return False
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None:
        if address.is_loopback:
            return address in {
                ipaddress.ip_address("127.0.0.1"),
                ipaddress.ip_address("::1"),
            }
        if not address.is_global:
            return False
    if parsed.scheme == "https":
        return True
    return False


def allowed_origins_from_environment() -> tuple[str, ...]:
    """Parse exact frontend origins; wildcard and URL paths are never accepted."""
    raw = environ.get("ALLOWED_ORIGINS", "")
    return validate_allowed_origins(
        tuple(dict.fromkeys(item.strip() for item in raw.split(",") if item.strip()))
    )


def scanner_api_token_from_environment() -> str | None:
    """Return a usable server-to-server credential, failing closed if missing/weak."""
    token = environ.get("SCANNER_API_TOKEN")
    if (
        not token
        or len(token) < _MIN_SCANNER_API_TOKEN_LENGTH
        or token.strip() != token
    ):
        return None
    return token


def validate_allowed_origins(origins: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    """Validate exact HTTP(S) origins supplied by code or environment."""
    normalized_origins: list[str] = []
    for raw_origin in origins:
        origin = raw_origin.strip()
        parsed = urlsplit(origin)
        try:
            hostname = parsed.hostname
            port = parsed.port
        except ValueError as exc:
            raise ValueError("ALLOWED_ORIGINS contains an invalid host or port.") from exc
        if (
            origin == "*"
            or not origin
            or parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or not hostname
            or (port is not None and port < 1)
            or parsed.netloc.endswith(":")
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("ALLOWED_ORIGINS must contain exact HTTP(S) origins without paths or wildcards.")

        scheme = parsed.scheme.casefold()
        host = hostname.casefold().rstrip(".")
        if "%" in host:
            raise ValueError("ALLOWED_ORIGINS cannot contain scoped IP literals.")
        try:
            address = ipaddress.ip_address(host)
            host = address.compressed
        except ValueError:
            address = None
            try:
                host = host.encode("idna").decode("ascii")
            except UnicodeError as exc:
                raise ValueError("ALLOWED_ORIGINS contains an invalid hostname.") from exc
        if scheme == "http" and host != "localhost" and not (
            address is not None and address.is_loopback
        ):
            raise ValueError("Non-local ALLOWED_ORIGINS must use HTTPS.")
        authority_host = f"[{host}]" if ":" in host else host
        if port == (443 if scheme == "https" else 80):
            port = None
        authority = authority_host + (f":{port}" if port is not None else "")
        normalized_origins.append(f"{scheme}://{authority}")
    return tuple(dict.fromkeys(normalized_origins))
