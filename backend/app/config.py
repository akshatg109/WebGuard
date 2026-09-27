"""Server-only Supabase settings for the future persistence integration."""

from dataclasses import dataclass
from os import environ
from urllib.parse import urlparse


@dataclass(frozen=True)
class SupabaseSettings:
    url: str | None
    publishable_key: str | None
    secret_key: str | None

    @classmethod
    def from_environment(cls) -> "SupabaseSettings":
        url = environ.get("SUPABASE_URL")
        if url:
            parsed = urlparse(url)
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
