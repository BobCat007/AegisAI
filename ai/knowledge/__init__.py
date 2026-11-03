"""Deterministic, provenance-preserving security knowledge and retrieval."""

from ai.knowledge.builder import SecurityKnowledgeBuilder
from ai.knowledge.chunker import KnowledgeChunk, KnowledgeChunker
from ai.knowledge.models import KnowledgeDocument, KnowledgeDocumentType
from ai.knowledge.retrieval import (
    KnowledgeRetriever,
    RetrievalHit,
    RetrievalQuery,
    RetrievalResult,
)

__all__ = [
    "KnowledgeDocument",
    "KnowledgeDocumentType",
    "SecurityKnowledgeBuilder",
    "KnowledgeChunk",
    "KnowledgeChunker",
    "KnowledgeRetriever",
    "RetrievalHit",
    "RetrievalQuery",
    "RetrievalResult",
]

from ai.knowledge.ingestion import (
    KnowledgeIngestionService,
    get_knowledge_ingestion_service,
    get_shared_knowledge_retriever,
)

__all__ += [
    "KnowledgeIngestionService",
    "get_knowledge_ingestion_service",
    "get_shared_knowledge_retriever",
]
