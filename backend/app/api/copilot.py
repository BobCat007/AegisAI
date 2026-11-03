"""AegisAI Security Copilot API."""

from fastapi import APIRouter, HTTPException

from ai.copilot.provider import CopilotProviderError, GeminiProvider
from ai.copilot.service import CopilotQuestion, SecurityCopilot
from ai.knowledge.ingestion import get_shared_knowledge_retriever

router = APIRouter(prefix="/api/copilot", tags=["Security Copilot"])

# Shared process-local knowledge index.
_knowledge_retriever = get_shared_knowledge_retriever()


def get_knowledge_retriever():
    """Return the shared retriever (overridable in tests)."""
    return _knowledge_retriever


@router.get("/status")
def copilot_status():
    provider = GeminiProvider()
    return {
        "provider": "google_gemini",
        "configured": provider.configured,
        "model": provider.model,
        "knowledge_index_size": get_knowledge_retriever().index_size,
        "retrieval": "hybrid_tfidf_exact",
    }


@router.post("/ask")
def ask_copilot(request: CopilotQuestion):
    retriever = get_knowledge_retriever()
    provider = GeminiProvider()
    copilot = SecurityCopilot(retriever, provider)
    try:
        return copilot.ask(request)
    except CopilotProviderError as exc:
        raise HTTPException(
            status_code=exc.status_code, detail=str(exc)
        ) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
