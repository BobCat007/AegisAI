from fastapi import FastAPI
from backend.app.security import enforce_api_security

from backend.app.api.authorization import router as authorization_router
from backend.app.api.behavioral import router as behavioral_router
from backend.app.api.copilot import router as copilot_router
from backend.app.api.discovery import router as discovery_router
from backend.app.api.risk import router as risk_router
from backend.app.api.telemetry import router as telemetry_router
from backend.app.api.investigation import router as investigation_router


app = FastAPI(
    title="AegisAI",
    description="Autonomous AI-Native API Security Platform",
    version="1.0.0-rc.1",
)


@app.middleware("http")
async def api_security_middleware(request, call_next):
    rejection = enforce_api_security(request)

    if rejection is not None:
        response = rejection
    else:
        response = await call_next(request)

    # Browser security headers apply to successful and rejected responses.
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=()"
    )

    return response


app.include_router(discovery_router)
app.include_router(risk_router)
app.include_router(behavioral_router)
app.include_router(authorization_router)
app.include_router(copilot_router)
app.include_router(telemetry_router)
app.include_router(investigation_router)


@app.get("/")
def root():
    return {
        "project": "AegisAI",
        "description": "Autonomous AI-Native API Security Platform",
        "version": "0.1.0",
        "status": "online",
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "AegisAI Backend",
    }
