import math

from ai.risk_prediction.evidence import SecurityEvidence
from ai.security_reasoning.models import (
    ReasoningEvidence,
    SecurityReasoningFinding,
    SecurityReasoningResult,
)
from api_discovery.models import (
    APIEndpoint,
    APIObjectOperationSurface,
)


class SecurityReasoningEngine:
    """
    Generate transparent, human-readable security reasoning.

    The engine identifies patterns that deserve security review.
    Structural indicators are not treated as proof of vulnerabilities.
    """

    def analyze_endpoint(
        self,
        endpoint: APIEndpoint,
        documented_evidence: list[SecurityEvidence] | None = None,
        object_surfaces: list[APIObjectOperationSurface] | None = None,
        shap_explanation=None,
    ) -> SecurityReasoningResult:

        documented_evidence = documented_evidence or []
        object_surfaces = object_surfaces or []

        classification = endpoint.security_classification
        findings: list[SecurityReasoningFinding] = []

        # Rule 1: Object-level authorization review.
        if classification.has_path_parameters:
            identifier_names = classification.object_identifier_names

            findings.append(
                SecurityReasoningFinding(
                    finding_id="BOLA-REVIEW",
                    category="bola_review",
                    title="Object-level authorization review recommended",
                    severity="medium",
                    confidence="medium",
                    explanation=(
                        "This endpoint accepts object identifiers in its "
                        "path. The API specification alone cannot establish "
                        "whether the requesting identity is authorized to "
                        "access the referenced object."
                    ),
                    evidence=[
                        ReasoningEvidence(
                            source="API endpoint classification",
                            detail=(
                                "Object identifiers detected: "
                                + ", ".join(identifier_names)
                            ),
                            reference=endpoint.path,
                        ),
                        ReasoningEvidence(
                            source="HTTP operation",
                            detail=f"The endpoint uses {endpoint.method}.",
                            reference=f"{endpoint.method} {endpoint.path}",
                        ),
                    ],
                    recommended_validation=[
                        "Create or identify two authorized test identities with separate owned objects.",
                        "Using the first identity, attempt to access the second identity's object.",
                        "Verify that the server enforces object ownership or an equivalent access policy.",
                    ],
                )
            )

        # Rule 2: Function-level authorization review.
        if classification.is_destructive:
            findings.append(
                SecurityReasoningFinding(
                    finding_id="BFLA-REVIEW",
                    category="bfla_review",
                    title="Function-level authorization review recommended",
                    severity="medium",
                    confidence="medium",
                    explanation=(
                        "This endpoint performs a destructive or modifying "
                        "operation. Verify that only identities with the "
                        "appropriate role or permission can invoke it."
                    ),
                    evidence=[
                        ReasoningEvidence(
                            source="API endpoint classification",
                            detail="The endpoint is classified as destructive.",
                            reference=f"{endpoint.method} {endpoint.path}",
                        )
                    ],
                    recommended_validation=[
                        "Identify the roles that are intended to perform this operation.",
                        "Test the operation with an authenticated identity that lacks the required permission.",
                        "Verify that unauthorized identities are denied and that no state change occurs.",
                    ],
                )
            )

        # Rule 3: Sensitive response data review.
        if classification.has_sensitive_response_fields:
            sensitive_fields = classification.sensitive_response_fields

            findings.append(
                SecurityReasoningFinding(
                    finding_id="SENSITIVE-DATA-REVIEW",
                    category="sensitive_data_review",
                    title="Sensitive response data exposure review recommended",
                    severity="high",
                    confidence="high",
                    explanation=(
                        "The documented response schema contains fields "
                        "whose names indicate sensitive information. "
                        "Confirm that these fields are necessary and are "
                        "returned only to appropriately authorized users."
                    ),
                    evidence=[
                        ReasoningEvidence(
                            source="OpenAPI response schema",
                            detail=(
                                "Sensitive response fields detected: "
                                + ", ".join(sensitive_fields)
                            ),
                            reference=f"{endpoint.method} {endpoint.path}",
                        )
                    ],
                    recommended_validation=[
                        "Inspect actual responses from the endpoint using authorized test accounts.",
                        "Verify that sensitive fields are required for the endpoint's intended purpose.",
                        "Check that access controls prevent unauthorized identities from receiving sensitive fields.",
                    ],
                )
            )

        # Rule 4: Destructive operation safeguards.
        if classification.is_destructive:
            findings.append(
                SecurityReasoningFinding(
                    finding_id="DESTRUCTIVE-OPERATION-REVIEW",
                    category="destructive_operation_review",
                    title="Destructive operation safeguards should be reviewed",
                    severity="medium",
                    confidence="high",
                    explanation=(
                        "The endpoint can modify or delete application "
                        "resources. Review authorization, input validation, "
                        "audit logging, and safeguards against unintended "
                        "state changes."
                    ),
                    evidence=[
                        ReasoningEvidence(
                            source="API endpoint classification",
                            detail="Destructive operation detected.",
                            reference=f"{endpoint.method} {endpoint.path}",
                        )
                    ],
                    recommended_validation=[
                        "Verify authorization before state-changing actions.",
                        "Verify that input validation rejects invalid targets.",
                        "Verify that security-relevant actions are audit logged.",
                        "Use a controlled test environment to verify that unintended state changes are prevented.",
                    ],
                )
            )

        # Rule 5: Graph-aware operation surface analysis.
        matching_surfaces = [
            surface
            for surface in object_surfaces
            if surface.path_template == endpoint.path
        ]

        for surface in matching_surfaces:
            methods = {
                method.upper()
                for method in surface.operations
            }

            has_read = "GET" in methods
            has_write = bool(
                methods.intersection({"POST", "PUT", "PATCH"})
            )
            has_delete = "DELETE" in methods

            mutation_methods = methods.intersection(
                {"POST", "PUT", "PATCH", "DELETE"}
            )

            graph_reference = surface.path_template

            graph_evidence = [
                ReasoningEvidence(
                    source="API security graph",
                    detail=(
                        "Object identifier names: "
                        + (
                            ", ".join(surface.object_identifier_names)
                            if surface.object_identifier_names
                            else "None"
                        )
                    ),
                    reference=graph_reference,
                ),
                ReasoningEvidence(
                    source="API security graph",
                    detail=(
                        "Available operations: "
                        + ", ".join(sorted(methods))
                    ),
                    reference=graph_reference,
                ),
            ]

            # Rule 5a: Mutation operations without GET.
            if mutation_methods and not has_read:
                findings.append(
                    SecurityReasoningFinding(
                        finding_id="GRAPH-MUTATION-WITHOUT-READ",
                        category="mutation_without_read_review",
                        title="Object mutation surface has no documented read operation",
                        severity="medium",
                        confidence="medium",
                        explanation=(
                            "The security graph identifies mutation "
                            "operations for this object but no GET operation "
                            "on the same path template. Review whether this "
                            "operation surface is intentional and whether "
                            "authorization and resource-state controls are "
                            "correctly enforced."
                        ),
                        evidence=graph_evidence,
                        recommended_validation=[
                            "Review whether the absence of a GET operation is intentional.",
                            "Verify authorization for every mutation operation on this object.",
                            "Check whether object ownership and resource-state validation are enforced.",
                        ],
                    )
                )

            # Rule 5b: DELETE without GET.
            if has_delete and not has_read:
                findings.append(
                    SecurityReasoningFinding(
                        finding_id="GRAPH-DELETE-WITHOUT-READ",
                        category="delete_without_read_review",
                        title="Object deletion surface has no documented read operation",
                        severity="medium",
                        confidence="medium",
                        explanation=(
                            "The security graph identifies a DELETE "
                            "operation without a GET operation for the same "
                            "object path template. Review deletion "
                            "authorization, object ownership, and intended "
                            "resource lifecycle behavior."
                        ),
                        evidence=graph_evidence,
                        recommended_validation=[
                            "Verify that deletion is restricted to authorized identities.",
                            "Test object ownership enforcement using separate test identities.",
                            "Confirm that deletion targets the intended object and follows expected lifecycle rules.",
                        ],
                    )
                )

            # Rule 5c: Multiple mutation methods.
            if len(mutation_methods) > 1:
                findings.append(
                    SecurityReasoningFinding(
                        finding_id="GRAPH-MULTIPLE-MUTATIONS",
                        category="multiple_mutation_types_review",
                        title="Object exposes multiple mutation operation types",
                        severity="low",
                        confidence="medium",
                        explanation=(
                            "The security graph identifies multiple "
                            "distinct mutation methods for the same object. "
                            "Review whether each operation has consistent "
                            "authorization, validation, and audit controls."
                        ),
                        evidence=graph_evidence,
                        recommended_validation=[
                            "Document the intended purpose of each mutation method.",
                            "Compare authorization requirements across mutation methods.",
                            "Verify consistent input validation and audit logging.",
                        ],
                    )
                )

        # Rule 6: Exact documented evidence match.
        matching_evidence = [
            item
            for item in documented_evidence
            if (
                item.path == endpoint.path
                and item.method.upper() == endpoint.method.upper()
            )
        ]

        for index, item in enumerate(matching_evidence, start=1):
            vulnerability_type = item.vulnerability_type.upper()

            findings.append(
                SecurityReasoningFinding(
                    finding_id=f"DOCUMENTED-REFERENCE-{index}",
                    category="documented_vulnerability_reference",
                    title=f"Documented {vulnerability_type} reference match",
                    severity="high",
                    confidence="high",
                    validation_status="documented_reference",
                    explanation=(
                        "This endpoint exactly matches an entry in the "
                        "configured security evidence catalog. This is a "
                        "documented reference match, not proof that the "
                        "currently assessed API instance is vulnerable."
                    ),
                    evidence=[
                        ReasoningEvidence(
                            source=item.source,
                            detail=item.description,
                            reference=", ".join(item.references) or None,
                        ),
                        ReasoningEvidence(
                            source="Security evidence catalog",
                            detail=(
                                f"Exact match for {item.method.upper()} "
                                f"{item.path}."
                            ),
                            reference=f"{item.method.upper()} {item.path}",
                        ),
                    ],
                    recommended_validation=[
                        "Verify that the assessed API operation has the same behavior as the documented reference.",
                        "Reproduce the relevant security test against an authorized test instance.",
                        "Record actual request and response evidence before treating the issue as confirmed.",
                    ],
                )
            )

        # Rule 7: Explain the predicted class using endpoint-specific SHAP.
        # SHAP contributions explain model scores; they are not vulnerability evidence.
        if shap_explanation is not None:
            predicted_class = getattr(shap_explanation, "predicted_label", None)
            class_explanations = getattr(
                shap_explanation, "class_explanations", []
            )
            predicted_explanation = next(
                (
                    item
                    for item in class_explanations
                    if getattr(item, "risk_class", None) == predicted_class
                ),
                None,
            )

            if predicted_explanation is not None:
                contributions = sorted(
                    getattr(predicted_explanation, "contributions", []),
                    key=lambda item: abs(float(getattr(item, "shap_value", 0.0))),
                    reverse=True,
                )

                usable_contributions = []
                for contribution in contributions:
                    try:
                        feature_value = float(contribution.feature_value)
                        shap_value = float(contribution.shap_value)
                    except (AttributeError, TypeError, ValueError):
                        continue

                    if not (
                        math.isfinite(feature_value)
                        and math.isfinite(shap_value)
                    ):
                        continue
                    if shap_value == 0:
                        continue

                    usable_contributions.append(
                        (contribution, feature_value, shap_value)
                    )
                    if len(usable_contributions) == 5:
                        break

                for index, (contribution, feature_value, shap_value) in enumerate(
                    usable_contributions
                ):
                    if index == 0:
                        category = "shap_dominant_feature"
                        finding_id = "SHAP-DOMINANT-FEATURE"
                        title = "Dominant feature in the predicted model score"
                    elif shap_value > 0:
                        category = "shap_risk_increasing_feature"
                        finding_id = f"SHAP-RISK-INCREASING-{index}"
                        title = "Feature increases the predicted class score"
                    else:
                        category = "shap_risk_decreasing_feature"
                        finding_id = f"SHAP-RISK-DECREASING-{index}"
                        title = "Feature decreases the predicted class score"

                    feature_name = str(contribution.feature_name)
                    direction = (
                        "increases" if shap_value > 0 else "decreases"
                    )
                    detail = (
                        f"Feature '{feature_name}' has value {feature_value} "
                        f"and SHAP contribution {shap_value:+.8f}; it "
                        f"{direction} the raw score for predicted class "
                        f"'{predicted_class}'."
                    )

                    findings.append(
                        SecurityReasoningFinding(
                            finding_id=finding_id,
                            category=category,
                            title=title,
                            severity="informational",
                            confidence="low",
                            explanation=(
                                "This is a model explanation, not evidence "
                                "that the endpoint is vulnerable. SHAP "
                                "contributions describe the feature's effect "
                                "on the model's raw predicted-class score; "
                                "they do not establish causality."
                            ),
                            evidence=[
                                ReasoningEvidence(
                                    source="SHAP model explanation",
                                    detail=detail,
                                    reference=(
                                        f"{endpoint.method.upper()} "
                                        f"{endpoint.path}"
                                    ),
                                )
                            ],
                            recommended_validation=[
                                "Inspect the feature's computation and confirm that its input data is correct.",
                                "Corroborate the model signal with independent API security evidence and authorized testing.",
                            ],
                        )
                    )

        # Determine the overall assessment.
        if any(
            item.validation_status == "documented_reference"
            for item in findings
        ):
            overall_assessment = "documented_reference_match"
            summary = (
                "The endpoint matches one or more entries in the "
                "documented security evidence catalog. Runtime validation "
                "is still required."
            )
        elif findings:
            overall_assessment = "review_recommended"
            summary = (
                f"{len(findings)} security review signal(s) were identified. "
                "These signals require validation and are not confirmed "
                "vulnerabilities."
            )
        else:
            overall_assessment = "no_review_signal"
            summary = (
                "No security reasoning rules were triggered by the "
                "available endpoint classification, graph, and evidence."
            )

        return SecurityReasoningResult(
            path=endpoint.path,
            method=endpoint.method.upper(),
            overall_assessment=overall_assessment,
            summary=summary,
            findings=findings,
            vulnerabilities_confirmed=False,
            limitations=[
                "OpenAPI schemas describe documented API structure; they do not prove runtime security behavior.",
                "Object identifiers and destructive operations are review signals, not proof of BOLA or BFLA.",
                "Graph operation patterns describe API structure and do not independently establish authorization failures.",
                "Documented evidence matches do not prove that the assessed API instance is vulnerable.",
                "Runtime authorization testing and supporting request/response evidence are required for confirmation.",
                "SHAP contributions explain model scores and do not prove vulnerabilities or causality; the risk model was trained on synthetic data.",
            ],
        )
