"""VibeShield FastAPI application entrypoint."""

from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from backend.app.api.router import api_router
from backend.app.schemas.health import HealthResponse

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
FRONTEND_DIR = REPO_ROOT / "frontend"

app = FastAPI(
    title="VibeShield API",
    description="AI Security Reviewer for Vibe-Coded Websites",
    version="0.1.0",
)

# Enable CORS for all origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health", response_model=HealthResponse, tags=["Health"])
def get_health() -> HealthResponse:
    """Readiness probe returning service status and readiness metadata."""
    return HealthResponse(
        status="ready",
        ready=True,
        service="VibeShield API",
        version="0.1.0",
    )


# API Routers
app.include_router(api_router, prefix="/api/v1")
app.include_router(api_router, prefix="/api")

# Mount Static Frontend
if FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
