"""Factory for a privileged Supabase client used only by server code."""

from supabase import AsyncClient, create_async_client

from app.config import SupabaseSettings


async def create_admin_client(
    settings: SupabaseSettings | None = None,
) -> AsyncClient:
    """Create an async backend client with the server-only Supabase secret key.

    Callers must authenticate the user separately and derive ownership from a
    verified JWT before using this RLS-bypassing client to persist user data.
    """
    configured = settings or SupabaseSettings.from_environment()
    url, _, secret_key = configured.require_configured()
    return await create_async_client(url, secret_key)
