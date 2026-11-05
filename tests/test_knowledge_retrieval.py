import pytest

from ai.knowledge import KnowledgeDocument, KnowledgeRetriever, RetrievalQuery


def document(document_id, title, content, *, doc_type="reasoning_finding", confirmed=False, source="test.source"):
    return KnowledgeDocument(
        document_id=document_id,
        document_type=doc_type,
        title=title,
        content=content,
        source=source,
        source_reference=f"ref:{document_id}",
        validation_status="not_validated",
        confirmed=confirmed,
    )


def test_retrieves_relevant_document_and_preserves_provenance():
    retriever = KnowledgeRetriever()
    retriever.add_documents([
        document("d1", "BOLA ownership review", "Check object ownership for GET /orders/{id}."),
        document("d2", "Rate limiting", "Review request throttling for login endpoints."),
    ])
    result = retriever.retrieve("object ownership orders", top_k=3)
    assert result.hits
    assert result.hits[0].document_id == "d1"
    assert result.hits[0].source_reference == "ref:d1"
    assert result.hits[0].validation_status == "not_validated"
    assert result.hits[0].confirmed is False


def test_empty_index_returns_empty_result():
    result = KnowledgeRetriever().retrieve("authorization review")
    assert result.hits == []
    assert result.index_size == 0


def test_duplicate_addition_is_idempotent():
    retriever = KnowledgeRetriever()
    doc = document("d1", "Authorization", "Check authorization policy.")
    assert retriever.add_documents([doc]) == 1
    assert retriever.add_documents([doc]) == 0
    assert retriever.index_size == 1


def test_filters_by_document_type_and_source():
    retriever = KnowledgeRetriever()
    retriever.add_documents([
        document("d1", "BOLA", "Object ownership check.", doc_type="authorization_finding", source="auth"),
        document("d2", "Anomaly", "Unusual request rate.", doc_type="behavioral_anomaly", source="behavior"),
    ])
    result = retriever.retrieve(RetrievalQuery(
        query="object ownership", document_types=["authorization_finding"], source="auth"
    ))
    assert [hit.document_id for hit in result.hits] == ["d1"]


def test_unconfirmed_filter_does_not_promote_findings():
    retriever = KnowledgeRetriever()
    retriever.add_documents([
        document("d1", "Unvalidated BOLA", "Object ownership mismatch.", confirmed=False),
        document("d2", "Confirmed BOLA", "Object ownership violation.", confirmed=True),
    ])
    result = retriever.retrieve(RetrievalQuery(query="object ownership", include_unconfirmed=False))
    assert [hit.document_id for hit in result.hits] == ["d2"]


def test_remove_document_rebuilds_index():
    retriever = KnowledgeRetriever()
    retriever.add_documents([document("d1", "BOLA", "Object ownership check.")])
    assert retriever.remove_document("d1") == 1
    assert retriever.index_size == 0
    assert retriever.retrieve("object ownership").hits == []


def test_chunker_bounds_chunk_size_and_count():
    from ai.knowledge.chunker import KnowledgeChunker

    doc = document("large", "Large", " ".join(f"word{i}" for i in range(1000)))
    chunker = KnowledgeChunker(max_words=40, overlap_words=5, max_chunks_per_document=3)
    chunks = chunker.chunk(doc)
    assert len(chunks) == 3
    assert all(len(chunk.text.split()) <= 40 for chunk in chunks)


def test_query_validation_rejects_excessive_top_k():
    with pytest.raises(Exception):
        RetrievalQuery(query="test", top_k=1000)


def test_retrieval_limitations_are_explicit():
    result = KnowledgeRetriever().retrieve("BOLA")
    assert any("not semantic" in item for item in result.limitations)
    assert any("in-memory" in item for item in result.limitations)


def test_behavioral_metadata_ranks_login_authentication_evidence_first():
    retriever = KnowledgeRetriever()

    login = document(
        "login-anomaly",
        "Behavioral anomalous assessment — POST /api/auth/login",
        "Classification: anomalous. Data origin: runtime. "
        "Authentication failure rate was unusually high.",
        doc_type="behavioral_anomaly",
    ).model_copy(update={
        "metadata": {
            "endpoint_path": "/api/auth/login",
            "method": "POST",
            "classification": "anomalous",
            "signals": [{
                "name": "auth_failure_rate",
                "observed": 0.94,
                "baseline_mean": 0.01,
            }],
        }
    })

    orders = document(
        "orders-anomaly",
        "Behavioral anomalous assessment — GET /api/orders",
        "Classification: anomalous. Unusual response size variation.",
        doc_type="behavioral_anomaly",
    ).model_copy(update={
        "metadata": {
            "endpoint_path": "/api/orders",
            "method": "GET",
            "classification": "anomalous",
            "signals": [{
                "name": "response_size_stddev_bytes",
                "observed": 500,
            }],
        }
    })

    retriever.add_documents([orders, login])

    result = retriever.retrieve(
        "Analyze behavioral telemetry evidence for authentication "
        "failures on the login endpoint. Explain observed anomaly, "
        "supporting evidence, and limitations.",
        top_k=5,
    )

    assert result.hits
    assert result.hits[0].document_id == "login-anomaly"
    assert result.hits[0].metadata["endpoint_path"] == "/api/auth/login"

def test_diversity_selection_avoids_duplicate_documents():
    retriever = KnowledgeRetriever()

    retriever.add_documents([
        document(
            "remediation-1",
            "Authorization remediation",
            "Apply server side authorization checks and validate resource ownership.",
            doc_type="remediation",
        ),
        document(
            "remediation-2",
            "Authorization remediation guidance",
            "Apply server side authorization checks and validate resource ownership.",
            doc_type="remediation",
        ),
        document(
            "bola-1",
            "BOLA object ownership finding",
            "Broken object level authorization occurs when a user can access "
            "another account's resource without ownership verification.",
            doc_type="authorization_finding",
        ),
        document(
            "behavior-1",
            "Behavioral anomaly detection",
            "Detect abnormal authentication failure rates and unusual API request patterns.",
            doc_type="behavioral_anomaly",
        ),
    ])

    result = retriever.retrieve(
        "Summarize relevant API authorization security findings and evidence",
        top_k=4,
    )

    document_ids = [hit.document_id for hit in result.hits]

    assert len(document_ids) == len(set(document_ids))
    assert "bola-1" in document_ids


def test_diversity_selection_preserves_remediation_intent():
    retriever = KnowledgeRetriever()

    retriever.add_documents([
        document(
            "finding-1",
            "Authorization finding",
            "Users may access another account's records without ownership verification.",
            doc_type="authorization_finding",
        ),
        document(
            "remediation-1",
            "Authorization remediation",
            "Prevent unauthorized access by enforcing server side ownership checks.",
            doc_type="remediation",
        ),
    ])

    result = retriever.retrieve(
        "How can we prevent unauthorized access and fix authorization issues?",
        top_k=2,
    )

    assert result.hits
    assert result.hits[0].document_type == "remediation"


def test_diversity_selection_returns_one_chunk_per_document():
    from ai.knowledge.retrieval import RetrievalHit

    def hit(chunk_id, document_id, score, content):
        return RetrievalHit(
            chunk_id=chunk_id,
            document_id=document_id,
            document_type="reasoning_finding",
            title="Security finding",
            text=content,
            source="test",
            source_reference=f"ref:{document_id}",
            score=score,
            lexical_score=score,
            exact_match_score=score,
            confirmed=False,
        )

    candidates = [
        hit("doc-1:0", "doc-1", 0.90, "authorization ownership access"),
        hit("doc-1:1", "doc-1", 0.85, "authorization ownership access"),
        hit("doc-2:0", "doc-2", 0.80, "behavioral anomaly request rate"),
    ]

    selected = KnowledgeRetriever._select_diverse_hits(
        candidates,
        top_k=3,
    )

    selected_ids = [item.document_id for item in selected]

    assert len(selected_ids) == 2
    assert len(selected_ids) == len(set(selected_ids))

def test_confirmed_findings_query_excludes_unconfirmed_documents():
    retriever = KnowledgeRetriever()

    retriever.add_documents([
        document(
            "confirmed-1",
            "Confirmed BOLA finding",
            "Object ownership violation was confirmed.",
            confirmed=True,
        ),
        document(
            "unconfirmed-1",
            "Unvalidated BOLA finding",
            "Possible object ownership issue.",
            confirmed=False,
        ),
    ])

    result = retriever.retrieve(
        "What are the confirmed security findings?",
        top_k=10,
    )

    assert result.hits
    assert all(hit.confirmed is True for hit in result.hits)
    assert [hit.document_id for hit in result.hits] == ["confirmed-1"]


def test_confirmed_findings_query_returns_empty_when_none_confirmed():
    retriever = KnowledgeRetriever()

    retriever.add_documents([
        document(
            "finding-1",
            "Documented BFLA reference",
            "A documented authorization reference.",
            confirmed=False,
        ),
    ])

    result = retriever.retrieve(
        "What are the confirmed security findings?",
        top_k=10,
    )

    assert result.hits == []
    assert result.total_candidates == 0

def test_general_security_query_still_includes_unconfirmed_documents():
    retriever = KnowledgeRetriever()

    retriever.add_documents([
        document(
            "finding-1",
            "Authorization finding",
            "Review object ownership authorization.",
            confirmed=False,
        ),
    ])

    result = retriever.retrieve(
        "Summarize authorization security findings.",
        top_k=5,
    )

    assert result.hits
    assert result.hits[0].confirmed is False
