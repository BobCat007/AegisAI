from ai.knowledge import KnowledgeDocument, KnowledgeRetriever


def make_doc(document_id, title, content, doc_type="reasoning_finding"):
    return KnowledgeDocument(
        document_id=document_id,
        document_type=doc_type,
        title=title,
        content=content,
        source="calibration_test",
        source_reference=f"calibration:{document_id}",
        validation_status="not_validated",
        confirmed=False,
    )


def build_calibration_retriever():
    retriever = KnowledgeRetriever()

    retriever.add_documents([
        make_doc(
            "bola-001",
            "BOLA object ownership assessment",
            (
                "Broken Object Level Authorization occurs when an API "
                "does not verify whether the authenticated user owns "
                "the requested object. Review GET /api/orders/{id}, "
                "compare the authenticated user ID with the resource "
                "owner ID, and enforce object-level access control."
            ),
            "authorization_finding",
        ),
        make_doc(
            "bfla-001",
            "BFLA function-level authorization assessment",
            (
                "Broken Function Level Authorization occurs when users "
                "can access functions or administrative endpoints "
                "outside their permitted role. Verify role permissions "
                "and enforce authorization on every restricted API "
                "operation."
            ),
            "authorization_finding",
        ),
        make_doc(
            "behavior-001",
            "Behavioral anomaly detection",
            (
                "Detect unusual API request rates, authentication "
                "failures, client error spikes, and abnormal response "
                "sizes. Isolation Forest can identify anomalous "
                "behavior compared with an established baseline."
            ),
            "behavioral_anomaly",
        ),
        make_doc(
            "remediation-001",
            "Authorization remediation guidance",
            (
                "Apply server-side authorization checks, validate "
                "resource ownership, enforce role-based permissions, "
                "deny unauthorized requests, prevent users from "
                "accessing another account's records, and log access failures."
            ),
            "remediation",
        ),
        make_doc(
            "database-001",
            "Database indexing fundamentals",
            (
                "Database indexes improve query performance by "
                "organizing records for efficient lookup. B-tree "
                "indexes support range queries and can reduce "
                "the number of disk operations."
            ),
        ),
    ])

    return retriever


CALIBRATION_CASES = [
    (
        "strongly_relevant",
        "How do we detect BOLA object ownership failures in API orders?",
        "bola-001",
    ),
    (
        "strongly_relevant",
        "How does Isolation Forest detect unusual API authentication failures?",
        "behavior-001",
    ),
    (
        "partially_relevant",
        "Explain authorization security checks",
        {"bola-001", "bfla-001", "remediation-001"},
    ),
    (
        "partially_relevant",
        "How should an API prevent unauthorized access?",
        {"remediation-001", "bola-001", "bfla-001"},
    ),
    (
        "unrelated",
        "Explain photosynthesis and chlorophyll absorption in plants",
        None,
    ),
]


def test_retrieval_calibration_score_report():
    retriever = build_calibration_retriever()

    print("\n========== RETRIEVAL CALIBRATION ==========")

    for category, question, expected_document in CALIBRATION_CASES:
        result = retriever.retrieve(question, top_k=5)

        print(f"\nCategory: {category}")
        print(f"Question: {question}")
        print(f"Expected document: {expected_document}")
        print(f"Returned hits: {len(result.hits)}")

        for hit in result.hits:
            print(
                f"  {hit.document_id}: "
                f"combined={hit.score:.4f}, "
                f"tfidf={hit.lexical_score:.4f}, "
                f"exact={hit.exact_match_score:.4f}"
            )

        if expected_document is None:
            assert not result.hits, (
                f"Unrelated question unexpectedly retrieved: "
                f"{[hit.document_id for hit in result.hits]}"
            )
        else:
            assert result.hits, f"No results for {category} question"
            acceptable = (expected_document if isinstance(expected_document, set) else {expected_document})
            assert result.hits[0].document_id in acceptable, (
                f"Unexpected top result for {question!r}: "
                f"{result.hits[0].document_id}"
            )

    print("\n========== CALIBRATION COMPLETE ==========")


def test_retrieval_handles_paraphrase_and_broad_queries():
    retriever = build_calibration_retriever()

    # A paraphrase that should retrieve authorization remediation.
    result = retriever.retrieve(
        "How can a server stop users accessing another account's records?",
        top_k=5,
    )
    assert result.hits
    assert result.hits[0].document_id == "remediation-001"

    # Broad queries should not receive perfect exact-match scores
    # merely because one token appears in a document.
    for question in ("authorization", "API"):
        result = retriever.retrieve(question, top_k=5)
        assert result.hits
        assert all(hit.exact_match_score < 1.0 for hit in result.hits)
