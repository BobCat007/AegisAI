"""Shared assessment-to-knowledge ingestion for AegisAI."""

from threading import RLock
from typing import Any

from ai.knowledge.builder import SecurityKnowledgeBuilder
from ai.knowledge.models import KnowledgeDocument
from ai.knowledge.retrieval import KnowledgeRetriever


class KnowledgeIngestionService:
    """Convert trusted assessment results into the shared Copilot index."""

    def __init__(
        self,
        retriever: KnowledgeRetriever | None = None,
        builder: SecurityKnowledgeBuilder | None = None,
    ) -> None:
        self.retriever = retriever or KnowledgeRetriever()
        self.builder = builder or SecurityKnowledgeBuilder()
        self._lock = RLock()

    @property
    def index_size(self) -> int:
        return self.retriever.index_size

    def ingest(self, documents: list[KnowledgeDocument]) -> int:
        """Add deterministic documents; duplicate chunks are ignored."""
        if not documents:
            return 0
        with self._lock:
            return self.retriever.add_documents(documents)

    def ingest_discovery(self, assessment: dict[str, Any]) -> int:
        """Ingest reasoning, correlations and remediation from Discovery."""
        if assessment.get("status") != "success":
            return 0

        documents: list[KnowledgeDocument] = []

        for endpoint in assessment.get("endpoint_assessments", []):
            if not isinstance(endpoint, dict):
                continue

            method = str(endpoint.get("method", "")).upper()
            path = str(endpoint.get("path", ""))
            endpoint_ref = f"{method} {path}".strip()

            reasoning = endpoint.get("security_reasoning")
            if not isinstance(reasoning, dict):
                continue

            reasoning_input = {
                **reasoning,
                "method": method,
                "path": path,
                "vulnerabilities_confirmed": (
                    assessment.get("vulnerabilities_confirmed") is True
                ),
            }
            documents.extend(self.builder.from_reasoning(reasoning_input))

            correlation = reasoning.get("evidence_correlation")
            if isinstance(correlation, dict):
                documents.extend(
                    self.builder.from_evidence_correlation(
                        correlation, endpoint_ref
                    )
                )

            remediation = reasoning.get("remediation_plan")
            if isinstance(remediation, dict):
                remediation_input = {
                    **remediation,
                    "method": method,
                    "path": path,
                }
                documents.extend(
                    self.builder.from_remediation(remediation_input)
                )

        # Attack chains are inferred structural paths, never confirmed exploits.
        attack_analysis = assessment.get("attack_chain_analysis", {})
        if isinstance(attack_analysis, dict):
            for index, chain in enumerate(attack_analysis.get("chains", [])):
                if isinstance(chain, dict):
                    chain_id = chain.get("chain_id") or chain.get("id") or index
                    documents.append(
                        self.builder.from_attack_chain(
                            chain,
                            f"attack_chain:{chain_id}",
                        )
                    )

        return self.ingest(documents)

    def ingest_authorization(
        self, finding: dict[str, Any], source_reference: str
    ) -> int:
        document = self.builder.from_authorization_finding(
            finding, source_reference
        )
        return self.ingest([document])

    def ingest_behavioral(
        self, results: list[dict[str, Any]], source_reference: str
    ) -> int:
        documents = [
            self.builder.from_behavioral_result(
                result,
                f"{source_reference}#{index}",
            )
            for index, result in enumerate(results)
            if isinstance(result, dict)
        ]
        return self.ingest(documents)


_shared_service = KnowledgeIngestionService()


def get_knowledge_ingestion_service() -> KnowledgeIngestionService:
    """Return the process-wide ingestion service."""
    return _shared_service


def get_shared_knowledge_retriever() -> KnowledgeRetriever:
    """Return the retriever shared by assessment APIs and Copilot."""
    return _shared_service.retriever
