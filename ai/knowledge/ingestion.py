"""Persistent assessment-to-knowledge ingestion for AegisAI."""

import json
import os
import tempfile
from pathlib import Path
from threading import RLock
from typing import Any

from ai.knowledge.builder import SecurityKnowledgeBuilder
from ai.knowledge.models import KnowledgeDocument
from ai.knowledge.normalizer import sanitize_text, sanitize_value
from ai.knowledge.retrieval import KnowledgeRetriever


DEFAULT_STORE_PATH = Path("data/knowledge/documents.jsonl")


class KnowledgeIngestionService:
    """Persist sanitized assessment documents and maintain the shared index."""

    def __init__(
        self,
        retriever: KnowledgeRetriever | None = None,
        builder: SecurityKnowledgeBuilder | None = None,
        store_path: str | Path | None = None,
    ) -> None:
        self.retriever = retriever or KnowledgeRetriever()
        self.builder = builder or SecurityKnowledgeBuilder()
        self.store_path = Path(store_path) if store_path is not None else None
        self._lock = RLock()
        self._documents: dict[str, KnowledgeDocument] = {}
        self._load_existing()

    @property
    def index_size(self) -> int:
        return self.retriever.index_size

    @staticmethod
    def _sanitize_document(document: KnowledgeDocument) -> KnowledgeDocument:
        """Re-sanitize records at the persistence boundary."""
        data = document.model_dump()
        for field in (
            "document_id",
            "title",
            "content",
            "source",
            "source_reference",
        ):
            data[field] = sanitize_text(data[field])

        for field in ("severity", "priority", "validation_status"):
            if data[field] is not None:
                data[field] = sanitize_text(data[field])

        data["metadata"] = sanitize_value(data["metadata"])
        return KnowledgeDocument.model_validate(data)

    def _load_existing(self) -> None:
        """Load valid JSONL documents and rebuild the in-memory index."""
        if self.store_path is None or not self.store_path.exists():
            return

        loaded: dict[str, KnowledgeDocument] = {}
        with self._lock:
            with self.store_path.open("r", encoding="utf-8") as handle:
                for line_number, line in enumerate(handle, start=1):
                    if not line.strip():
                        continue
                    try:
                        document = KnowledgeDocument.model_validate(
                            json.loads(line)
                        )
                        document = self._sanitize_document(document)
                        loaded[document.document_id] = document
                    except (ValueError, TypeError, json.JSONDecodeError):
                        # Ignore malformed or incompatible records without
                        # preventing the rest of the knowledge base loading.
                        continue

            self._documents = loaded
            if loaded:
                self.retriever.add_documents(loaded.values())

    def _persist(self, documents: dict[str, KnowledgeDocument]) -> None:
        """Atomically replace the JSONL store with the current document set."""
        if self.store_path is None:
            return
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        temp_path: str | None = None

        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=self.store_path.parent,
                prefix=f".{self.store_path.name}.",
                suffix=".tmp",
                delete=False,
            ) as handle:
                temp_path = handle.name
                for document_id in sorted(documents):
                    handle.write(
                        documents[document_id].model_dump_json() + "\n"
                    )
                handle.flush()
                os.fsync(handle.fileno())

            os.replace(temp_path, self.store_path)
            temp_path = None
        finally:
            if temp_path and os.path.exists(temp_path):
                os.unlink(temp_path)

    def ingest(self, documents: list[KnowledgeDocument]) -> int:
        """Persist documents and add new or changed records to the index."""
        if not documents:
            return 0

        with self._lock:
            updated = dict(self._documents)
            changed: list[KnowledgeDocument] = []

            for document in documents:
                if not isinstance(document, KnowledgeDocument):
                    document = KnowledgeDocument.model_validate(document)

                safe_document = self._sanitize_document(document)
                previous = updated.get(safe_document.document_id)

                if previous == safe_document:
                    continue

                updated[safe_document.document_id] = safe_document
                changed.append(safe_document)

            if not changed:
                return 0

            # Persist first: if disk writing fails, the in-memory index and
            # document registry remain unchanged.
            self._persist(updated)

            added_chunks = 0
            for document in changed:
                self.retriever.remove_document(document.document_id)
                added_chunks += self.retriever.add_documents([document])

            self._documents = updated
            return added_chunks

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

        attack_analysis = assessment.get("attack_chain_analysis", {})
        if isinstance(attack_analysis, dict):
            for index, chain in enumerate(attack_analysis.get("chains", [])):
                if isinstance(chain, dict):
                    chain_id = chain.get("chain_id") or chain.get("id") or index
                    documents.append(
                        self.builder.from_attack_chain(
                            chain, f"attack_chain:{chain_id}"
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
                result, f"{source_reference}#{index}"
            )
            for index, result in enumerate(results)
            if isinstance(result, dict)
        ]
        return self.ingest(documents)


_shared_service = KnowledgeIngestionService(store_path=DEFAULT_STORE_PATH)


def get_knowledge_ingestion_service() -> KnowledgeIngestionService:
    """Return the process-wide ingestion service."""
    return _shared_service


def get_shared_knowledge_retriever() -> KnowledgeRetriever:
    """Return the retriever shared by assessment APIs and Copilot."""
    return _shared_service.retriever
