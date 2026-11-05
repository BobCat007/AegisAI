from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Iterable

from pydantic import BaseModel, ConfigDict, Field
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from ai.knowledge.chunker import KnowledgeChunk, KnowledgeChunker
from ai.knowledge.models import KnowledgeDocument


_TOKEN_RE = re.compile(r"[a-zA-Z0-9_]+")

_METADATA_STOP_WORDS = {
    "a", "an", "and", "are", "as", "at", "by",
    "for", "from", "in", "is", "of", "on", "or",
    "the", "to", "with",
}

_TOKEN_ALIASES = {
    "bola": {"bola", "idor", "object", "level", "authorization"},
    "idor": {"idor", "bola", "object", "level", "authorization"},
    "bfla": {"bfla", "function", "level", "authorization"},
    "authorization": {"authorization", "authorize", "access", "permission"},
    "authorized": {"authorization", "authorize", "access", "permission"},
    "unauthorized": {"authorization", "access", "permission", "unauthorized"},
    "vulnerability": {"vulnerability", "vulnerabilities", "security", "issue"},
    "vulnerabilities": {"vulnerability", "vulnerabilities", "security", "issue"},
    "remediation": {"remediation", "mitigation", "fix", "mitigate"},
    "mitigation": {"remediation", "mitigation", "fix", "mitigate"},
    "prevent": {"prevent", "protection", "mitigation", "secure"},
    "preventing": {"prevent", "protection", "mitigation", "secure"},
    "confirmed": {"confirmed", "verified", "validated"},
    "verified": {"confirmed", "verified", "validated"},
    "validated": {"confirmed", "verified", "validated"},
}


def _normalized_tokens(value: str) -> set[str]:
    """Return normalized tokens with common security aliases."""
    tokens = {
        token.lower()
        for token in _TOKEN_RE.findall(value or "")
    }

    expanded = set(tokens)

    for token in tokens:
        expanded.update(_TOKEN_ALIASES.get(token, set()))

    return expanded


def _metadata_tokens(value: str) -> set[str]:
    """Normalize text while excluding common stop words."""
    return {
        token
        for token in _normalized_tokens(value)
        if token not in _METADATA_STOP_WORDS
    }


def _requires_confirmed_only(query: str) -> bool:
    """Detect explicit requests for confirmed or verified findings."""
    normalized = " ".join((query or "").lower().split())

    patterns = (
        r"\bconfirmed\s+(security\s+)?(findings|vulnerabilities|issues)\b",
        r"\b(only|show|list|display)\s+(the\s+)?confirmed\b",
        r"\bverified\s+(security\s+)?(findings|vulnerabilities|issues)\b",
        r"\bvalidated\s+(security\s+)?(findings|vulnerabilities|issues)\b",
    )

    return any(
        re.search(pattern, normalized)
        for pattern in patterns
    )


def _content_similarity(left: str, right: str) -> float:
    """Calculate token Jaccard similarity between two text values."""
    left_tokens = _normalized_tokens(left)
    right_tokens = _normalized_tokens(right)

    if not left_tokens or not right_tokens:
        return 0.0

    union = left_tokens | right_tokens

    if not union:
        return 0.0

    return len(left_tokens & right_tokens) / len(union)


class RetrievalQuery(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: str
    top_k: int = Field(default=5, ge=1, le=100)
    document_types: list[str] = Field(default_factory=list)
    source: str | None = None
    include_unconfirmed: bool = True
    confirmed_only: bool = False


@dataclass
class RetrievalHit:
    chunk_id: str
    document_id: str
    document_type: str
    title: str
    text: str
    source: str
    source_reference: str
    score: float
    lexical_score: float = 0.0
    exact_match_score: float = 0.0
    severity: str | None = None
    priority: str | None = None
    confidence: float | None = None
    confirmed: bool = False
    validation_status: str | None = None
    metadata: dict = field(default_factory=dict)

    @property
    def content(self) -> str:
        """Compatibility alias for consumers using content."""
        return self.text


@dataclass
class RetrievalResult:
    query: str
    hits: list[RetrievalHit]
    total_candidates: int
    index_size: int
    retrieval_method: str = "hybrid_tfidf_exact_metadata"
    limitations: list[str] = field(default_factory=list)


class KnowledgeRetriever:
    """Hybrid lexical, exact-token, and metadata knowledge retriever."""

    def __init__(
        self,
        chunker: KnowledgeChunker | None = None,
    ) -> None:
        self.chunker = chunker or KnowledgeChunker()
        self._chunks: dict[str, KnowledgeChunk] = {}
        self._vectorizer: TfidfVectorizer | None = None
        self._matrix = None
        self._chunk_ids: list[str] = []

    @property
    def index_size(self) -> int:
        """Return the number of indexed chunks."""
        return len(self._chunks)

    def add_documents(
        self,
        documents: Iterable[KnowledgeDocument],
    ) -> int:
        """Chunk and add new or changed knowledge documents."""
        added_count = 0

        for document in documents:
            if not isinstance(document, KnowledgeDocument):
                document = KnowledgeDocument.model_validate(document)

            chunks = self.chunker.chunk(document)

            for chunk in chunks:
                previous = self._chunks.get(chunk.chunk_id)

                if previous == chunk:
                    continue

                self._chunks[chunk.chunk_id] = chunk
                added_count += 1

        if added_count:
            self._rebuild_index()

        return added_count

    def add_chunks(self, chunks: Iterable[KnowledgeChunk]) -> int:
        """Add or replace already-created chunks."""
        added_count = 0

        for chunk in chunks:
            previous = self._chunks.get(chunk.chunk_id)

            if previous == chunk:
                continue

            self._chunks[chunk.chunk_id] = chunk
            added_count += 1

        if added_count:
            self._rebuild_index()

        return added_count

    def remove_document(self, document_id: str) -> int:
        """Remove all chunks belonging to a document."""
        matching_ids = [
            chunk_id
            for chunk_id, chunk in self._chunks.items()
            if chunk.document_id == document_id
        ]

        for chunk_id in matching_ids:
            del self._chunks[chunk_id]

        if matching_ids:
            self._rebuild_index()

        return len(matching_ids)

    def _rebuild_index(self) -> None:
        """Rebuild the TF-IDF index from stored chunks."""
        self._chunk_ids = list(self._chunks.keys())

        if not self._chunk_ids:
            self._vectorizer = None
            self._matrix = None
            return

        documents = [
            self._chunks[chunk_id].text
            for chunk_id in self._chunk_ids
        ]

        self._vectorizer = TfidfVectorizer(
            lowercase=True,
            token_pattern=r"(?u)\b\w+\b",
            ngram_range=(1, 2),
            sublinear_tf=True,
        )

        try:
            self._matrix = self._vectorizer.fit_transform(documents)
        except ValueError:
            self._vectorizer = None
            self._matrix = None

    @staticmethod
    def _metadata_score(
        query_tokens: set[str],
        chunk: KnowledgeChunk,
    ) -> float:
        """Calculate metadata overlap with the query."""
        if not query_tokens:
            return 0.0

        metadata = chunk.metadata or {}

        metadata_text = " ".join(
            [
                chunk.title,
                chunk.document_type,
                chunk.source,
                " ".join(
                    f"{key} {value}"
                    for key, value in metadata.items()
                ),
            ]
        )

        metadata_tokens = _metadata_tokens(metadata_text)

        if not metadata_tokens:
            return 0.0

        return len(query_tokens & metadata_tokens) / len(query_tokens)

    @staticmethod
    def _exact_score(
        query_tokens: set[str],
        chunk: KnowledgeChunk,
        broad_query: bool = False,
    ) -> float:
        """Calculate exact token overlap with the document chunk."""
        if not query_tokens:
            return 0.0

        content_tokens = _normalized_tokens(
            f"{chunk.title} {chunk.text}"
        )

        if not content_tokens:
            return 0.0

        overlap = len(query_tokens & content_tokens)
        score = overlap / len(query_tokens)

        # Broad single-word queries must not receive perfect scores.
        if broad_query:
            return min(score, 0.5)

        return score

    @staticmethod
    def _select_diverse_hits(
        hits: list[RetrievalHit],
        top_k: int,
        relevance_weight: float = 0.8,
    ) -> list[RetrievalHit]:
        """Select relevant results while reducing duplicate content."""
        if not hits or top_k <= 0:
            return []

        remaining = sorted(
            hits,
            key=lambda hit: hit.score,
            reverse=True,
        )

        selected: list[RetrievalHit] = []
        selected_document_ids: set[str] = set()

        while remaining and len(selected) < top_k:
            best_hit = None
            best_score = -math.inf

            for candidate in remaining:
                if candidate.document_id in selected_document_ids:
                    continue

                max_similarity = max(
                    (
                        _content_similarity(
                            candidate.text,
                            chosen.text,
                        )
                        for chosen in selected
                    ),
                    default=0.0,
                )

                diversity_score = (
                    relevance_weight * candidate.score
                    - (1.0 - relevance_weight) * max_similarity
                )

                if diversity_score > best_score:
                    best_score = diversity_score
                    best_hit = candidate

            if best_hit is None:
                break

            selected.append(best_hit)
            selected_document_ids.add(best_hit.document_id)
            remaining.remove(best_hit)

        return selected

    def retrieve(
        self,
        request: RetrievalQuery | str,
        top_k: int = 5,
    ) -> RetrievalResult:
        """Retrieve relevant knowledge using hybrid ranking."""
        if isinstance(request, str):
            request = RetrievalQuery(
                query=request,
                top_k=top_k,
            )

        query = (request.query or "").strip()

        if not query:
            return RetrievalResult(
                query=query,
                hits=[],
                total_candidates=0,
                index_size=self.index_size,
                limitations=self._limitations(),
            )

        confirmed_only = (
            request.confirmed_only
            or _requires_confirmed_only(query)
            or not request.include_unconfirmed
        )

        candidates = [
            chunk
            for chunk in self._chunks.values()
            if (
                not request.document_types
                or chunk.document_type in request.document_types
            )
            and (
                request.source is None
                or chunk.source == request.source
            )
            and (
                not confirmed_only
                or chunk.confirmed is True
            )
        ]

        if not candidates:
            return RetrievalResult(
                query=query,
                hits=[],
                total_candidates=0,
                index_size=self.index_size,
                limitations=self._limitations(),
            )

        raw_query_tokens = _TOKEN_RE.findall(query)
        broad_query = len(raw_query_tokens) == 1

        query_tokens = _metadata_tokens(query)

        lexical_scores: dict[str, float] = {
            chunk.chunk_id: 0.0
            for chunk in candidates
        }

        if self._vectorizer is not None and self._matrix is not None:
            try:
                filtered_query = " ".join(sorted(query_tokens))
                query_vector = self._vectorizer.transform(
                    [filtered_query]
                )

                similarities = cosine_similarity(
                    query_vector,
                    self._matrix,
                ).flatten()

                for index, chunk_id in enumerate(self._chunk_ids):
                    lexical_scores[chunk_id] = float(
                        similarities[index]
                    )

            except ValueError:
                pass

        hits: list[RetrievalHit] = []

        for chunk in candidates:
            lexical_score = lexical_scores.get(
                chunk.chunk_id,
                0.0,
            )

            exact_score = self._exact_score(
                query_tokens,
                chunk,
                broad_query=broad_query,
            )

            metadata_score = self._metadata_score(
                query_tokens,
                chunk,
            )

            base_score = min(
                1.0,
                0.75 * lexical_score + 0.25 * exact_score,
            )

            final_score = min(
                1.0,
                base_score
                + 0.35 * metadata_score * (1.0 - base_score),
            )

            if final_score <= 0.0:
                continue

            hits.append(
                RetrievalHit(
                    chunk_id=chunk.chunk_id,
                    document_id=chunk.document_id,
                    document_type=chunk.document_type,
                    title=chunk.title,
                    text=chunk.text,
                    source=chunk.source,
                    source_reference=chunk.source_reference,
                    score=final_score,
                    lexical_score=lexical_score,
                    exact_match_score=exact_score,
                    severity=chunk.severity,
                    priority=chunk.priority,
                    confidence=chunk.confidence,
                    confirmed=chunk.confirmed,
                    validation_status=chunk.validation_status,
                    metadata=chunk.metadata or {},
                )
            )

        selected_hits = self._select_diverse_hits(
            hits,
            request.top_k,
        )

        return RetrievalResult(
            query=query,
            hits=selected_hits,
            total_candidates=len(candidates),
            index_size=self.index_size,
            limitations=self._limitations(),
        )

    @staticmethod
    def _limitations() -> list[str]:
        return [
            "Retrieval is not semantic; it uses lexical TF-IDF, "
            "exact-token matching, and metadata overlap rather than "
            "semantic embeddings.",
            "Retrieval scores are ranking signals, not confidence "
            "or vulnerability severity measurements.",
            "Retrieved findings are not independently validated "
            "by the retrieval process.",
            "The knowledge index is in-memory and must be rebuilt "
            "from persisted knowledge after restart.",
            "Diversity selection may return results in an order "
            "that differs from their original relevance scores.",
        ]
