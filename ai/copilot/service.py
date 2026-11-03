"""Retrieval-augmented security question answering."""

from __future__ import annotations

import re

from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field

from ai.copilot.prompts import SYSTEM_INSTRUCTIONS, format_evidence
from ai.knowledge.retrieval import KnowledgeRetriever, RetrievalQuery


class TextGenerationProvider(Protocol):
    model: str

    def generate(
        self, *, instructions: str, evidence: str, question: str
    ) -> tuple[str, str | None]: ...


class CopilotQuestion(BaseModel):
    model_config = ConfigDict(extra="forbid")
    question: str = Field(min_length=3, max_length=4000)
    top_k: int = Field(default=5, ge=1, le=10)
    document_types: list[str] = Field(default_factory=list, max_length=10)
    include_unconfirmed: bool = True


class CopilotAnswer(BaseModel):
    model_config = ConfigDict(extra="forbid")
    answer: str
    model: str
    response_id: str | None = None
    retrieval_method: str
    retrieved_count: int
    citations: list[dict]
    limitations: list[str]


class SecurityCopilot:
    def __init__(
        self,
        retriever: KnowledgeRetriever,
        provider: TextGenerationProvider,
    ) -> None:
        self.retriever = retriever
        self.provider = provider

    def ask(self, request: CopilotQuestion) -> CopilotAnswer:
        result = self.retriever.retrieve(RetrievalQuery(
            query=request.question,
            top_k=request.top_k,
            document_types=request.document_types,
            include_unconfirmed=request.include_unconfirmed,
        ))
        hits = result.hits

        limitations = list(result.limitations)
        limitations.extend([
            "Model output is not independent security validation; it is an explanation of retrieved context.",
            "Citations identify retrieved records and do not imply that a finding is confirmed.",
            "The current knowledge index is in-memory and resets when the backend restarts.",
        ])

        # Do not call the external model when retrieval provides no evidence.
        if not hits:
            limitations.append(
                "No matching knowledge records were retrieved. The question was not sent to Gemini, and no project-specific conclusion can be drawn."
            )
            return CopilotAnswer(
                answer=(
                    "I cannot answer this from the current AegisAI knowledge base "
                    "because no matching evidence was retrieved. Run a relevant "
                    "assessment or ingest supporting records, then ask again."
                ),
                model=self.provider.model,
                response_id=None,
                retrieval_method=result.retrieval_method,
                retrieved_count=0,
                citations=[],
                limitations=limitations,
            )

        evidence = format_evidence(hits)
        answer, response_id = self.provider.generate(
            instructions=SYSTEM_INSTRUCTIONS,
            evidence=evidence,
            question=request.question,
        )

        # Only allow citation IDs that exist in the retrieved evidence.
        allowed_document_ids = {hit.document_id for hit in hits}
        cited_document_ids = set(
            re.findall(r"\[([A-Za-z0-9_.:-]+)\]", answer)
        )
        unsupported_citations = cited_document_ids - allowed_document_ids

        if unsupported_citations:
            limitations.append(
                "Unsupported citation IDs were rejected because they were not present in retrieved evidence."
            )

        if unsupported_citations:
            answer = (
                "I could not provide a reliably cited answer because the "
                "generated response contained citation IDs that were not "
                "present in the retrieved evidence. Please retry the question."
            )
            response_id = None
            limitations.append(
                "The generated answer was replaced because it cited document IDs that were not retrieved."
            )

        citations = [
            {
                "document_id": hit.document_id,
                "chunk_id": hit.chunk_id,
                "document_type": hit.document_type,
                "title": hit.title,
                "source": hit.source,
                "source_reference": hit.source_reference,
                "validation_status": hit.validation_status,
                "confirmed": hit.confirmed,
                "relevance_score": hit.score,
            }
            for hit in hits
        ]
        return CopilotAnswer(
            answer=answer,
            model=self.provider.model,
            response_id=response_id,
            retrieval_method=result.retrieval_method,
            retrieved_count=len(hits),
            citations=citations,
            limitations=limitations,
        )
