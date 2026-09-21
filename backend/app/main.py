from fastapi import FastAPI

app = FastAPI(
    title="AegisAI",
    description="Autonomous AI-Native API Security Platform",
    version="0.1.0",
)


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
