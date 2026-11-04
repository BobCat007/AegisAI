from __future__ import annotations

import re
from collections import Counter
from typing import Iterable

from pydantic import BaseModel, ConfigDict, Field
from sklearn.feature_extraction.text import ENGLISH_STOP_WORDS, TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from ai.knowledge.chunker import KnowledgeChunk, KnowledgeChunker
from ai.knowledge.models import KnowledgeDocument
from ai.knowledge.normalizer import sanitize_text


_TOKEN_RE = re.compile(r"[a-zA-Z0-9_./:{}-]+")

_METADATA_STOP_WORDS = ENGLISH_STOP_WORDS | {
    "analyze", "analysis", "behavioral", "telemetry", "evidence",
    "explain", "observed", "observation", "anomaly", "anomalies",
    "supporting", "limitations", "limitation", "endpoint",
}

_TOKEN_ALIASES = {
    "authentication": "auth",
    "authenticating": "auth",
    "authenticated": "auth",
    "failures": "failure",
    "failed": "failure",
    "failing": "failure",
    "logins": "login",
    "credentials": "credential",
    "signin": "login",
}


def _normalized_tokens(value: object) -> set[str]:
    """Extract searchable tokens and normalize common security terminology."""
    tokens: set[str] = set()
    for raw in _TOKEN_RE.findall(str(value).lower()):
        for part in re.split(r"[_./:{}-]+", raw):
            if not part or part in ENGLISH_STOP_WORDS:
                continue
            tokens.add(_TOKEN_ALIASES.get(part, part))
    return tokens


def _metadata_tokens(metadata: dict) -> set[str]:
    """Extract tokens from structured behavioral metadata."""
    values: list[str] = [
        str(metadata.get("endpoint_path", "")),
        str(metadata.get("method", "")),
        str(metadata.get("classification", "")),
    ]

    def collect(value: object) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                values.append(str(key))
                collect(item)
        elif isinstance(value, (list, tuple)):
            for item in value:
                collect(item)
        elif isinstance(value, str):
            values.append(value)

    collect(metadata.get("signals", []))
    return _normalized_tokens(" ".join(values))


class RetrievalQuery(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: str = Field(min_length=1, max_length=4000)
    top_k: int = Field(default=5, ge=1, le=50)
    document_types: list[str] = Field(default_factory=list, max_length=10)
    source: str | None = Field(default=None, max_length=200)
    include_unconfirmed: bool = True


class RetrievalHit(BaseModel):
    model_config = ConfigDict(extra="forbid")

    chunk_id: str
    document_id: str
    document_type: str
    title: str
    text: str
    source: str
    source_reference: str
    score: float = Field(ge=0.0, le=1.0)
    lexical_score: float = Field(ge=0.0, le=1.0)
    exact_match_score: float = Field(ge=0.0, le=1.0)
    severity: str | None = None
    priority: str | None = None
    confidence: float | None = None
    validation_status: str | None = None
    confirmed: bool = False
    metadata: dict = Field(default_factory=dict)


class RetrievalResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: str
    hits: list[RetrievalHit]
    total_candidates: int
    index_size: int
    retrieval_method: str = "hybrid_tfidf_exact_metadata"
    limitations: list[str] = Field(default_factory=list)


class KnowledgeRetriever:
    """In-memory hybrid lexical retriever; it does not claim semantic understanding."""

    def __init__(self, chunker: KnowledgeChunker | None = None):
        self.chunker = chunker or KnowledgeChunker()
        self._chunks: dict[str, KnowledgeChunk] = {}
        self._vectorizer: TfidfVectorizer | None = None
        self._matrix = None
        self._ordered_ids: list[str] = []

    @property
    def index_size(self) -> int:
        return len(self._chunks)

    def clear(self) -> None:
        self._chunks.clear()
        self._vectorizer = None
        self._matrix = None
        self._ordered_ids = []

    def add_documents(self, documents: Iterable[KnowledgeDocument]) -> int:
        added = 0
        for document in documents:
            if not isinstance(document, KnowledgeDocument):
                document = KnowledgeDocument.model_validate(document)
            for chunk in self.chunker.chunk(document):
                if chunk.chunk_id not in self._chunks:
                    self._chunks[chunk.chunk_id] = chunk
                    added += 1
        self._rebuild()
        return added

    def remove_document(self, document_id: str) -> int:
        to_remove = [
            chunk_id for chunk_id, chunk in self._chunks.items()
            if chunk.document_id == document_id
        ]
        for chunk_id in to_remove:
            del self._chunks[chunk_id]
        self._rebuild()
        return len(to_remove)

    def retrieve(self, request: RetrievalQuery | str, *, top_k: int | None = None) -> RetrievalResult:
        if isinstance(request, str):
            request = RetrievalQuery(query=request, top_k=top_k or 5)
        elif top_k is not None:
            request = request.model_copy(update={"top_k": top_k})

        query = sanitize_text(request.query).strip()
        if not query:
            raise ValueError("Query must contain searchable text")

        candidates = [
            chunk for chunk in self._chunks.values()
            if (not request.document_types or chunk.document_type in request.document_types)
            and (request.source is None or chunk.source == request.source)
            and (request.include_unconfirmed or chunk.confirmed)
        ]
        if not candidates:
            return RetrievalResult(
                query=query, hits=[], total_candidates=0, index_size=self.index_size,
                limitations=self._limitations(),
            )

        query_tokens = [
            token.lower() for token in _TOKEN_RE.findall(query)
            if token.lower() not in ENGLISH_STOP_WORDS
        ]
        focused_query_tokens = {
            _TOKEN_ALIASES.get(part, part)
            for token in query_tokens
            for part in re.split(r"[_./:{}-]+", token)
            if part and part not in _METADATA_STOP_WORDS
        }
        candidate_ids = {chunk.chunk_id for chunk in candidates}
        lexical_scores: dict[str, float] = {}
        if self._vectorizer is not None and self._matrix is not None:
            query_vector = self._vectorizer.transform([query])
            scores = cosine_similarity(query_vector, self._matrix).ravel()
            lexical_scores = {
                chunk_id: float(scores[index])
                for index, chunk_id in enumerate(self._ordered_ids)
                if chunk_id in candidate_ids
            }

        hits: list[RetrievalHit] = []
        for chunk in candidates:
            text = f"{chunk.title} {chunk.text}".lower()
            tokens = [token.lower() for token in _TOKEN_RE.findall(text)]
            counts = Counter(tokens)
            unique_query_tokens = set(query_tokens)
            exact = (
                sum(1 for token in unique_query_tokens if counts[token] > 0)
                / len(unique_query_tokens)
                if len(unique_query_tokens) >= 3
                else 0.0
            )
            lexical = lexical_scores.get(chunk.chunk_id, 0.0)
            base_score = min(1.0, 0.75 * lexical + 0.25 * exact)

            metadata_tokens = _metadata_tokens(chunk.metadata or {})
            metadata_score = (
                len(focused_query_tokens & metadata_tokens)
                / len(focused_query_tokens)
                if focused_query_tokens
                else 0.0
            )

            # Structured metadata improves ranking without replacing
            # the existing lexical and exact-match relevance signals.
            score = min(
                1.0,
                base_score + 0.35 * metadata_score * (1.0 - base_score),
            )
            if score <= 0:
                continue
            hits.append(RetrievalHit(
                chunk_id=chunk.chunk_id,
                document_id=chunk.document_id,
                document_type=chunk.document_type,
                title=chunk.title,
                text=chunk.text,
                source=chunk.source,
                source_reference=chunk.source_reference,
                score=score,
                lexical_score=lexical,
                exact_match_score=exact,
                severity=chunk.severity,
                priority=chunk.priority,
                confidence=chunk.confidence,
                validation_status=chunk.validation_status,
                confirmed=chunk.confirmed,
                metadata=chunk.metadata,
            ))

        hits.sort(key=lambda item: (-item.score, item.document_id, item.chunk_id))
        return RetrievalResult(
            query=query,
            hits=hits[:request.top_k],
            total_candidates=len(candidates),
            index_size=self.index_size,
            limitations=self._limitations(),
        )

    def _rebuild(self) -> None:
        self._ordered_ids = sorted(self._chunks)
        if not self._ordered_ids:
            self._vectorizer = None
            self._matrix = None
            return
        corpus = [
            f"{self._chunks[chunk_id].title} {self._chunks[chunk_id].text}"
            for chunk_id in self._ordered_ids
        ]
        self._vectorizer = TfidfVectorizer(
            lowercase=True,
            stop_words="english",
            ngram_range=(1, 2),
            max_features=50000,
            token_pattern=r"(?u)\b[\w./:{}-]+\b",
            sublinear_tf=True,
        )
        try:
            self._matrix = self._vectorizer.fit_transform(corpus)
        except ValueError:
            self._vectorizer = None
            self._matrix = None

    @staticmethod
    def _limitations() -> list[str]:
        return [
            "Retrieval combines TF-IDF, exact token overlap, and structured metadata token matching; it is not semantic embedding search.",
            "Scores are relevance-ranking signals, not confidence or vulnerability probabilities.",
            "Retrieved records preserve their source validation status; retrieval does not validate findings.",
            "The index is in-memory and must be rebuilt after application restart.",
        ]
