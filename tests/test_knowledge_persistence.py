import json

from ai.knowledge.ingestion import KnowledgeIngestionService
from ai.knowledge.models import KnowledgeDocument
from ai.knowledge.retrieval import KnowledgeRetriever


def make_document(document_id="doc-1", content="API authorization weakness"):
    return KnowledgeDocument(
        document_id=document_id,
        document_type="reasoning_finding",
        title="Authorization finding",
        content=content,
        source="security_reasoning",
        source_reference="GET /api/users",
        confirmed=False,
        metadata={"endpoint": "/api/users"},
    )


def test_documents_survive_service_restart(tmp_path):
    store = tmp_path / "knowledge" / "documents.jsonl"

    first = KnowledgeIngestionService(store_path=store)
    assert first.ingest([make_document()]) > 0
    original_size = first.index_size

    restarted = KnowledgeIngestionService(
        retriever=KnowledgeRetriever(),
        store_path=store,
    )

    assert restarted.index_size == original_size
    result = restarted.retriever.retrieve("API authorization weakness")
    assert result.hits
    assert result.hits[0].document_id == "doc-1"


def test_duplicate_ingestion_does_not_duplicate_persisted_records(tmp_path):
    store = tmp_path / "documents.jsonl"
    service = KnowledgeIngestionService(store_path=store)
    document = make_document()

    assert service.ingest([document]) > 0
    assert service.ingest([document]) == 0

    records = [
        json.loads(line)
        for line in store.read_text(encoding="utf-8").splitlines()
    ]
    assert len(records) == 1


def test_changed_document_replaces_old_index_content(tmp_path):
    store = tmp_path / "documents.jsonl"
    service = KnowledgeIngestionService(store_path=store)

    service.ingest([make_document(content="old authorization finding")])
    service.ingest([make_document(content="updated authorization finding")])

    assert service.retriever.retrieve("updated authorization finding").hits
    indexed_content = " ".join(str(chunk) for chunk in service.retriever._chunks.values())
    assert "old authorization finding" not in indexed_content


def test_malformed_jsonl_record_does_not_block_recovery(tmp_path):
    store = tmp_path / "documents.jsonl"
    valid = make_document().model_dump_json()
    store.write_text(
        valid + "\n" + "{malformed json\n",
        encoding="utf-8",
    )

    service = KnowledgeIngestionService(
        retriever=KnowledgeRetriever(),
        store_path=store,
    )

    assert service.index_size > 0
    assert service.retriever.retrieve("API authorization weakness").hits


def test_persisted_document_is_sanitized(tmp_path):
    store = tmp_path / "documents.jsonl"
    document = make_document(
        content="Authorization: Bearer super-secret-token"
    )

    service = KnowledgeIngestionService(store_path=store)
    service.ingest([document])

    persisted = json.loads(store.read_text(encoding="utf-8").splitlines()[0])
    assert "super-secret-token" not in persisted["content"]
    assert "[REDACTED]" in persisted["content"]
