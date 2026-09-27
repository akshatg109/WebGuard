from fastapi import FastAPI

app = FastAPI(
    title="WebGuard Scanning API",
    description="Foundation API for authorized, passive website configuration analysis.",
    version="0.1.0",
)


@app.get("/health", tags=["health"])
def health_check() -> dict[str, str]:
    """Report that the API process is ready to accept requests."""
    return {"status": "ok"}
