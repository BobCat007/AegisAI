from types import SimpleNamespace

from ai.security_reasoning.engine import SecurityReasoningEngine


def make_endpoint():
    classification = SimpleNamespace(
        has_path_parameters=False,
        object_identifier_names=[],
        is_destructive=False,
        has_sensitive_response_fields=False,
        sensitive_response_fields=[],
    )
    return SimpleNamespace(
        path="/api/items/{item_id}",
        method="GET",
        security_classification=classification,
    )


def contribution(name, value, shap):
    return SimpleNamespace(
        feature_name=name,
        feature_value=value,
        shap_value=shap,
    )


def explanation(predicted_label="high"):
    return SimpleNamespace(
        predicted_label=predicted_label,
        class_explanations=[
            SimpleNamespace(
                risk_class="low",
                contributions=[
                    contribution("wrong_class_feature", 1, 99.0),
                ],
            ),
            SimpleNamespace(
                risk_class="high",
                contributions=[
                    contribution("dominant", 3, 0.8),
                    contribution("positive", 2, 0.4),
                    contribution("negative", 1, -0.2),
                    contribution("zero", 0, 0.0),
                ],
            ),
        ],
    )


def test_shap_uses_only_predicted_class_and_sorts_contributions():
    result = SecurityReasoningEngine().analyze_endpoint(
        make_endpoint(),
        shap_explanation=explanation(),
    )

    shap_findings = [
        finding for finding in result.findings
        if finding.category.startswith("shap_")
    ]

    assert [finding.category for finding in shap_findings] == [
        "shap_dominant_feature",
        "shap_risk_increasing_feature",
        "shap_risk_decreasing_feature",
    ]
    assert "wrong_class_feature" not in str(shap_findings)
    assert "zero" not in str(shap_findings)


def test_shap_evidence_is_traceable_and_preserves_signed_value():
    result = SecurityReasoningEngine().analyze_endpoint(
        make_endpoint(),
        shap_explanation=explanation(),
    )

    dominant = next(
        finding for finding in result.findings
        if finding.category == "shap_dominant_feature"
    )
    evidence = dominant.evidence[0]

    assert evidence.source == "SHAP model explanation"
    assert "dominant" in evidence.detail
    assert "3.0" in evidence.detail
    assert "+0.80000000" in evidence.detail
    assert "high" in evidence.detail
    assert evidence.reference == "GET /api/items/{item_id}"
    assert dominant.severity == "informational"
    assert dominant.confidence == "low"
    assert dominant.validation_status == "not_validated"


def test_shap_negative_contribution_is_classified_as_decreasing():
    result = SecurityReasoningEngine().analyze_endpoint(
        make_endpoint(),
        shap_explanation=explanation(),
    )

    negative = next(
        finding for finding in result.findings
        if finding.category == "shap_risk_decreasing_feature"
    )
    assert "-0.20000000" in negative.evidence[0].detail


def test_shap_findings_never_confirm_vulnerabilities():
    result = SecurityReasoningEngine().analyze_endpoint(
        make_endpoint(),
        shap_explanation=explanation(),
    )

    assert result.vulnerabilities_confirmed is False
    assert any("SHAP contributions" in item for item in result.limitations)


def test_missing_shap_explanation_preserves_existing_behavior():
    result = SecurityReasoningEngine().analyze_endpoint(make_endpoint())

    assert result.findings == []
    assert result.overall_assessment == "no_review_signal"
    assert result.vulnerabilities_confirmed is False


def test_non_finite_shap_values_are_ignored():
    invalid_explanation = SimpleNamespace(
        predicted_label="high",
        class_explanations=[
            SimpleNamespace(
                risk_class="high",
                contributions=[
                    contribution("nan_feature", 1, float("nan")),
                    contribution("infinite_feature", 1, float("inf")),
                    contribution("valid_feature", 2, 0.5),
                ],
            )
        ],
    )

    result = SecurityReasoningEngine().analyze_endpoint(
        make_endpoint(),
        shap_explanation=invalid_explanation,
    )

    shap_findings = [
        finding for finding in result.findings
        if finding.category.startswith("shap_")
    ]
    assert len(shap_findings) == 1
    assert "valid_feature" in shap_findings[0].evidence[0].detail
