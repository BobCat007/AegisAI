from fastapi import FastAPI
from backend.app.security import enforce_api_security

from backend.app.api.authorization import router as authorization_router
from backend.app.api.behavioral import router as behavioral_router
from backend.app.api.copilot import router as copilot_router
from backend.app.api.discovery import router as discovery_router
from backend.app.api.risk import router as risk_router


app = FastAPI(
    title="AegisAI",
    description="Autonomous AI-Native API Security Platform",
    version="0.1.0",
)


@app.middleware("http")
async def api_security_middleware(request, call_next):
    rejection = enforce_api_security(request)
    if rejection is not None:
        return rejection
    return await call_next(request)


app.include_router(discovery_router)
app.include_router(risk_router)
app.include_router(behavioral_router)
app.include_router(authorization_router)
app.include_router(copilot_router)


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
