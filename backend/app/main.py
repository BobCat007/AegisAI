from fastapi import FastAPI

from backend.app.api.discovery import router as discovery_router


app = FastAPI(
    title="AegisAI",
    description="Autonomous AI-Native API Security Platform",
    version="0.1.0",
)


app.include_router(discovery_router)


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
