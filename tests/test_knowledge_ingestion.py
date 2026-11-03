


from ai.knowledge.ingestion import KnowledgeIngestionService
from ai.knowledge.retrieval import KnowledgeRetriever


def test_attack_chain_ingestion_is_idempotent_and_remains_unconfirmed():
    service = KnowledgeIngestionService(retriever=KnowledgeRetriever())
    assessment = {
        "status": "success",
        "vulnerabilities_confirmed": False,
        "endpoint_assessments": [],
        "attack_chain_analysis": {
            "chains": [{
                "chain_id": "chain-regression-1",
                "resources": ["users", "orders"],
                "relationships": [],
                "hop_count": 1,
                "confidence": 0.9,
                "evidence_sources": ["openapi"],
                "interpretation": "Inferred structural path; not a confirmed exploit.",
            }]
        },
    }

    first_added = service.ingest_discovery(assessment)
    second_added = service.ingest_discovery(assessment)

    assert first_added > 0
    assert second_added == 0
    assert service.index_size > 0

    result = service.retriever.retrieve(
        "inferred API resource path users orders",
        top_k=10,
    )
    hits = [hit for hit in result.hits if hit.document_type == "attack_chain"]

    assert hits
    hit = hits[0]
    assert hit.source_reference == "attack_chain:chain-regression-1"
    assert hit.validation_status == "structurally_inferred"
    assert hit.confirmed is False


def test_discovery_ingestion_ignores_non_success_assessments():
    service = KnowledgeIngestionService(retriever=KnowledgeRetriever())
    added = service.ingest_discovery({
        "status": "error",
        "endpoint_assessments": [],
        "attack_chain_analysis": {"chains": [{
            "chain_id": "must-not-index",
            "resources": ["users", "orders"],
            "relationships": [],
            "hop_count": 1,
            "confidence": 0.9,
            "evidence_sources": ["openapi"],
        }]},
    })
    assert added == 0
    assert service.index_size == 0
