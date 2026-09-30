"""WebGuard FastAPI application factory and health route."""

from __future__ import annotations

from contextlib import asynccontextmanager, suppress
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse

from app.ai.provider import AiProvider, OpenAICompatibleProvider
from app.api.ai import cached_ai_response
from app.api.ai import router as ai_router
from app.api.auth import SupabaseTokenVerifier, TokenVerifier
from app.api.errors import ApiError
from app.api.rate_limit import InMemoryPerUserRateLimiter, InMemoryScanRateLimiter
from app.api.request_limits import ScanRequestSizeLimitMiddleware
from app.api.scans import router as scans_router
from app.config import (
    AiProviderSettings,
    AiRateLimitSettings,
    ScanRateLimitSettings,
    SupabaseSettings,
    allowed_origins_from_environment,
    scanner_api_token_from_environment,
    validate_allowed_origins,
)
from app.persistence.ai import AiRepository, SupabaseAiRepository
from app.persistence.scans import ScanRepository, SupabaseScanRepository
from app.scanner.service import ScannerService
from app.supabase_client import create_admin_client


def create_app(
    *,
    scanner_service: Any | None = None,
    supabase_client: Any | None = None,
    scan_repository: ScanRepository | None = None,
    token_verifier: TokenVerifier | None = None,
    scan_rate_limiter: InMemoryScanRateLimiter | None = None,
    ai_provider: AiProvider | None = None,
    ai_repository: AiRepository | None = None,
    ai_rate_limiter: InMemoryPerUserRateLimiter | None = None,
    scanner_api_token: str | None = None,
    allowed_origins: tuple[str, ...] | list[str] | None = None,
) -> FastAPI:
    """Build an app with optional controlled dependencies for deterministic tests."""
    configured_origins = (
        validate_allowed_origins(allowed_origins)
        if allowed_origins is not None
        else allowed_origins_from_environment()
    )

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        application.state.scanner_service = scanner_service or ScannerService()
        application.state.scan_rate_limiter = (
            scan_rate_limiter or InMemoryScanRateLimiter(ScanRateLimitSettings.from_environment())
        )
        application.state.ai_rate_limiter = ai_rate_limiter or InMemoryPerUserRateLimiter(
            AiRateLimitSettings.from_environment()
        )
        application.state.scanner_api_token = (
            scanner_api_token
            if scanner_api_token is not None
            else scanner_api_token_from_environment()
        )
        application.state.supabase_client = supabase_client
        application.state.owns_supabase_client = False
        if application.state.supabase_client is None:
            settings = SupabaseSettings.from_environment()
            if settings.url and settings.publishable_key and settings.secret_key:
                application.state.supabase_client = await create_admin_client(settings)
                application.state.owns_supabase_client = True

        application.state.scan_repository = scan_repository or SupabaseScanRepository(
            application.state.supabase_client
        )
        provider_settings = AiProviderSettings.from_environment()
        application.state.ai_provider = ai_provider or (
            OpenAICompatibleProvider(provider_settings) if provider_settings is not None else None
        )
        application.state.ai_repository = ai_repository or SupabaseAiRepository(
            application.state.supabase_client
        )
        application.state.token_verifier = token_verifier or (
            SupabaseTokenVerifier(application.state.supabase_client)
            if application.state.supabase_client is not None
            else None
        )
        yield
        if application.state.owns_supabase_client:
            client = application.state.supabase_client
            with suppress(Exception):
                await client.auth.close()
            with suppress(Exception):
                await client.postgrest.aclose()

    application = FastAPI(
        title="WebGuard Scanning API",
        description="Authenticated API for safe, passive website configuration analysis.",
        version="0.2.0",
        lifespan=lifespan,
    )

    if configured_origins:
        application.add_middleware(
            CORSMiddleware,
            allow_origins=list(configured_origins),
            allow_credentials=False,
            allow_methods=["GET", "POST"],
            allow_headers=["Authorization", "Content-Type"],
        )
    application.add_middleware(ScanRequestSizeLimitMiddleware)

    @application.exception_handler(ApiError)
    async def api_error_handler(_request: Request, exc: ApiError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            headers=exc.headers,
            content={"error": {"code": exc.code, "message": exc.message}},
        )

    @application.exception_handler(RequestValidationError)
    async def validation_error_handler(
        _request: Request, _exc: RequestValidationError
    ) -> JSONResponse:
        # Do not echo input bodies, which may contain credentials or URL queries.
        return JSONResponse(
            status_code=422,
            content={
                "error": {
                    "code": "invalid_request",
                    "message": "The request is invalid. Check the supplied fields and try again.",
                }
            },
        )

    @application.exception_handler(Exception)
    async def unexpected_error_handler(_request: Request, _exc: Exception) -> JSONResponse:
        return JSONResponse(
            status_code=500,
            content={"error": {"code": "internal_error", "message": "The request could not be completed."}},
        )

    application.include_router(scans_router)
    application.include_router(ai_router)

    @application.get("/health", tags=["health"])
    def health_check() -> dict[str, str]:
        """Report that the API process is ready to accept requests."""
        return {"status": "ok"}

    def scanner_openapi() -> dict[str, Any]:
        """Document the BFF credential and user token as jointly required."""
        if application.openapi_schema is not None:
            return application.openapi_schema
        schema = get_openapi(
            title=application.title,
            version=application.version,
            description=application.description,
            routes=application.routes,
        )
        joint_security = [{"ScannerServiceToken": [], "SupabaseAccessToken": []}]
        for path, path_item in schema["paths"].items():
            if path.startswith("/api/scans"):
                for method in ("get", "post"):
                    operation = path_item.get(method)
                    if operation is not None:
                        operation["security"] = joint_security
        application.openapi_schema = schema
        return schema

    application.openapi = scanner_openapi
    return application


app = create_app()
