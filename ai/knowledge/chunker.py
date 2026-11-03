from __future__ import annotations

import re
from dataclasses import dataclass

from ai.knowledge.models import KnowledgeDocument
from ai.knowledge.normalizer import sanitize_text


@dataclass(frozen=True)
class KnowledgeChunk:
    chunk_id: str
    document_id: str
    document_type: str
    title: str
    text: str
    source: str
    source_reference: str
    severity: str | None
    priority: str | None
    confidence: float | None
    validation_status: str | None
    confirmed: bool
    metadata: dict


class KnowledgeChunker:
    """Create bounded, provenance-preserving chunks from knowledge documents."""

    def __init__(self, max_words: int = 180, overlap_words: int = 30, max_chunks_per_document: int = 100):
        if max_words < 20:
            raise ValueError("max_words must be at least 20")
        if overlap_words < 0 or overlap_words >= max_words:
            raise ValueError("overlap_words must be >= 0 and < max_words")
        if max_chunks_per_document < 1:
            raise ValueError("max_chunks_per_document must be positive")
        self.max_words = max_words
        self.overlap_words = overlap_words
        self.max_chunks_per_document = max_chunks_per_document

    def chunk(self, document: KnowledgeDocument) -> list[KnowledgeChunk]:
        title = sanitize_text(document.title)
        content = sanitize_text(document.content)
        words = content.split()
        if not words:
            words = [title]
        step = self.max_words - self.overlap_words
        chunks: list[KnowledgeChunk] = []
        for index, start in enumerate(range(0, len(words), step)):
            if index >= self.max_chunks_per_document:
                break
            body = " ".join(words[start:start + self.max_words])
            if not body:
                continue
            chunks.append(KnowledgeChunk(
                chunk_id=f"{document.document_id}:{index}",
                document_id=document.document_id,
                document_type=document.document_type,
                title=title,
                text=body,
                source=document.source,
                source_reference=document.source_reference,
                severity=document.severity,
                priority=document.priority,
                confidence=document.confidence,
                validation_status=document.validation_status,
                confirmed=document.confirmed,
                metadata=document.metadata,
            ))
        return chunks
