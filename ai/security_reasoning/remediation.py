from typing import Literal

from pydantic import BaseModel, Field

from ai.security_reasoning.models import (
    RiskPrioritizationAssessment,
    SecurityReasoningResult,
)


RemediationPriority = Literal[
    "informational",
    "low",
    "medium",
    "high",
    "critical",
]


class SecurityRemediation(BaseModel):
    remediation_id: str
    finding_id: str
    category: str
    title: str
    priority: RemediationPriority
    endpoint: str
    objective: str
    remediation_steps: list[str] = Field(default_factory=list)
    validation_steps: list[str] = Field(default_factory=list)
    evidence_references: list[str] = Field(default_factory=list)
    evidence_sources: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class RemediationPlan(BaseModel):
    path: str
    method: str
    endpoint_priority_score: int = Field(ge=0, le=100)
    endpoint_priority_level: str
    total_recommendations: int = Field(ge=0)
    recommendations: list[SecurityRemediation] = Field(
        default_factory=list
    )
    summary: str
    limitations: list[str] = Field(default_factory=list)


class RemediationEngine:
    """
    Generate deterministic, category-specific remediation guidance.

    Recommendations are based on existing reasoning findings.
    They do not independently establish that a vulnerability exists.
    """

    TEMPLATES = {
        "bola_review": {
            "title": "Strengthen object-level authorization",
            "objective": (
                "Ensure users can access only objects they are authorized "
                "to access."
            ),
            "remediation": [
                "Enforce object ownership or equivalent authorization checks on the server for every request.",
                "Derive the requesting identity from the authenticated server-side session or token.",
                "Do not rely on object identifiers supplied by the client as proof of authorization.",
                "Apply the same authorization policy consistently across read, update, and delete operations.",
                "Return an appropriate denial response without exposing protected object data.",
            ],
            "validation": [
                "Create two test identities with separate objects.",
                "Authenticate as the first identity and request the second identity's object.",
                "Repeat the test for read and mutation operations where applicable.",
                "Verify unauthorized requests are denied and no protected data or state changes are exposed.",
                "Retest authorized access to ensure legitimate users retain access.",
            ],
        },
        "bfla_review": {
            "title": "Enforce function-level authorization",
            "objective": (
                "Restrict sensitive operations to identities with the "
                "required role or permission."
            ),
            "remediation": [
                "Define the roles and permissions permitted to invoke this operation.",
                "Enforce authorization on the server before executing the operation.",
                "Apply deny-by-default behavior when permissions are missing or cannot be evaluated.",
                "Avoid relying only on frontend visibility or client-side role checks.",
                "Record security-relevant authorization denials in audit logs.",
            ],
            "validation": [
                "Test with an identity that has the required permission.",
                "Test with an authenticated identity that lacks the permission.",
                "Test with an unauthenticated identity if authentication is required.",
                "Verify unauthorized requests are denied before application state changes.",
                "Verify authorized requests continue to work.",
            ],
        },
        "sensitive_data_review": {
            "title": "Minimize and protect sensitive response data",
            "objective": (
                "Ensure responses disclose only the information required "
                "by the endpoint's intended purpose."
            ),
            "remediation": [
                "Review every identified sensitive response field and establish whether it is necessary.",
                "Use explicit response schemas or allowlists instead of serializing complete internal objects.",
                "Apply field-level authorization where different roles require different response data.",
                "Exclude credentials, tokens, secrets, and internal-only attributes unless explicitly required.",
                "Apply appropriate cache controls to responses containing sensitive information.",
            ],
            "validation": [
                "Inspect actual responses using accounts with different permissions.",
                "Verify unnecessary sensitive fields are absent.",
                "Verify required fields remain available to authorized identities.",
                "Check that sensitive responses are not unintentionally cached.",
                "Add regression tests for response-field exposure.",
            ],
        },
        "destructive_operation_review": {
            "title": "Protect state-changing operations",
            "objective": (
                "Prevent unauthorized, invalid, or unintended resource "
                "modifications and deletions."
            ),
            "remediation": [
                "Enforce authorization before performing any state-changing action.",
                "Validate resource identifiers, request parameters, and resource state on the server.",
                "Use transactions or equivalent safeguards where partial changes could leave inconsistent state.",
                "Implement idempotency or duplicate-request protection where appropriate.",
                "Maintain audit records for security-relevant changes and deletions.",
            ],
            "validation": [
                "Test authorized and unauthorized requests in a controlled environment.",
                "Submit invalid identifiers and malformed parameters.",
                "Verify rejected operations do not modify application state.",
                "Verify duplicate requests behave according to the documented operation contract.",
                "Confirm audit records contain the expected actor, action, target, and outcome.",
            ],
        },
        "documented_vulnerability_reference": {
            "title": "Verify and address the documented security reference",
            "objective": (
                "Determine whether the documented issue applies to the "
                "assessed implementation and address the underlying cause."
            ),
            "remediation": [
                "Compare the assessed endpoint's implementation and behavior with the documented security reference.",
                "Identify the underlying authorization, validation, or data-handling control involved.",
                "Implement the appropriate server-side security control for the confirmed root cause.",
                "Review related endpoints that use the same implementation or authorization mechanism.",
                "Document the change and its expected security behavior.",
            ],
            "validation": [
                "Reproduce the documented behavior only in an authorized test environment.",
                "Capture the relevant request, response, identity, and resource context.",
                "Apply the fix and repeat the same test.",
                "Verify the insecure behavior is no longer reproducible.",
                "Run regression tests for authorized behavior and related endpoints.",
            ],
        },
        "mutation_without_read_review": {
            "title": "Review authorization across object mutation operations",
            "objective": (
                "Ensure object mutation operations enforce consistent "
                "authorization and resource-state controls."
            ),
            "remediation": [
                "Document the intended lifecycle and supported operations for the object.",
                "Enforce object-level authorization independently for every mutation operation.",
                "Validate the current resource state before applying a mutation.",
                "Ensure mutation handlers do not trust client-supplied ownership or permission attributes.",
                "Review whether a documented read operation is required by the intended API design.",
            ],
            "validation": [
                "Test each mutation operation with authorized and unauthorized identities.",
                "Attempt cross-user object modifications using separate test identities.",
                "Verify invalid resource states are rejected.",
                "Verify failed operations do not partially modify resources.",
                "Confirm the documented operation surface matches the intended API design.",
            ],
        },
        "delete_without_read_review": {
            "title": "Strengthen object deletion controls",
            "objective": (
                "Ensure deletion is authorized, intentional, and restricted "
                "to the correct resource."
            ),
            "remediation": [
                "Verify object ownership or the required administrative permission before deletion.",
                "Validate that the target resource exists and is in a deletable state.",
                "Apply appropriate confirmation, retention, or recovery safeguards based on business requirements.",
                "Prevent clients from selecting resources outside their authorized scope.",
                "Record deletion actions in an auditable event log.",
            ],
            "validation": [
                "Attempt deletion using an authorized identity.",
                "Attempt deletion of another identity's resource.",
                "Test deletion of nonexistent and invalid resource identifiers.",
                "Verify rejected requests leave the resource unchanged.",
                "Verify deletion audit records and expected resource lifecycle behavior.",
            ],
        },
        "multiple_mutation_types_review": {
            "title": "Standardize controls across mutation methods",
            "objective": (
                "Ensure all mutation methods apply consistent authorization, "
                "validation, and auditing."
            ),
            "remediation": [
                "Document the intended behavior of each mutation method.",
                "Centralize shared authorization checks where practical.",
                "Apply consistent input validation and resource-state checks.",
                "Ensure partial updates cannot modify fields outside the caller's permissions.",
                "Apply consistent audit logging across all mutation methods.",
            ],
            "validation": [
                "Test each mutation method independently.",
                "Compare authorization behavior across all mutation methods.",
                "Test malformed and unauthorized field updates.",
                "Verify audit records are generated consistently.",
                "Add regression tests for method-specific behavior.",
            ],
        },
        "shap_dominant_feature": {
            "title": "Investigate the dominant model feature",
            "objective": (
                "Determine whether the dominant model feature reflects "
                "accurate and relevant API assessment data."
            ),
            "remediation": [
                "Inspect the feature's definition and source data.",
                "Verify that feature extraction uses the intended endpoint and graph scope.",
                "Check for missing, malformed, or incorrectly transformed input values.",
                "Compare the feature with independent security evidence.",
                "Do not change production security controls solely because of a SHAP contribution.",
            ],
            "validation": [
                "Recalculate the feature from the original assessment inputs.",
                "Check feature extraction against known test cases.",
                "Compare model behavior with and without the feature in a controlled evaluation.",
                "Corroborate any security concern with direct API testing.",
            ],
        },
        "shap_risk_increasing_feature": {
            "title": "Investigate the risk-increasing model feature",
            "objective": (
                "Verify the input and interpretation of a feature that "
                "increases the predicted class score."
            ),
            "remediation": [
                "Inspect the feature's source and calculation.",
                "Verify that the feature represents the intended endpoint property.",
                "Check for data quality issues and unexpected feature values.",
                "Correlate the signal with independent structural or runtime evidence.",
                "Avoid treating a model contribution as proof of a vulnerability.",
            ],
            "validation": [
                "Recalculate the feature using the original endpoint data.",
                "Test feature extraction with representative positive and negative cases.",
                "Review the model prediction alongside independent security evidence.",
                "Perform authorized security tests for any resulting review concern.",
            ],
        },
        "shap_risk_decreasing_feature": {
            "title": "Review the risk-decreasing model feature",
            "objective": (
                "Ensure a feature that lowers the predicted class score "
                "does not obscure an independent security concern."
            ),
            "remediation": [
                "Verify the feature's source and calculation.",
                "Check whether the feature is being interpreted within the correct model class.",
                "Review whether the feature can mask security concerns in combination with other inputs.",
                "Do not use a negative SHAP contribution as evidence that an endpoint is secure.",
            ],
            "validation": [
                "Recalculate the feature from the original assessment data.",
                "Review the complete predicted-class explanation.",
                "Compare the model result with baseline risk and independent evidence.",
                "Use direct security testing to evaluate any suspected issue.",
            ],
        },
    }

    def generate(
        self,
        reasoning: SecurityReasoningResult,
        risk_prioritization: RiskPrioritizationAssessment | None = None,
    ) -> RemediationPlan:
        endpoint = f"{reasoning.method.upper()} {reasoning.path}"

        priority_score = (
            risk_prioritization.priority_score
            if risk_prioritization is not None
            else 0
        )
        priority_level = (
            risk_prioritization.priority_level
            if risk_prioritization is not None
            else "not_assessed"
        )

        recommendations = []

        for finding in reasoning.findings:
            template = self.TEMPLATES.get(finding.category)

            if template is None:
                continue

            evidence_references = sorted(
                {
                    item.reference
                    for item in finding.evidence
                    if item.reference
                }
            )

            evidence_sources = sorted(
                {
                    item.source
                    for item in finding.evidence
                    if item.source
                }
            )

            recommendations.append(
                SecurityRemediation(
                    remediation_id=f"REMEDIATE-{finding.finding_id}",
                    finding_id=finding.finding_id,
                    category=finding.category,
                    title=template["title"],
                    priority=finding.severity,
                    endpoint=endpoint,
                    objective=template["objective"],
                    remediation_steps=template["remediation"],
                    validation_steps=template["validation"],
                    evidence_references=evidence_references,
                    evidence_sources=evidence_sources,
                    limitations=[
                        "This recommendation is generated from a security review signal, not a confirmed vulnerability.",
                        "Verify that the recommendation applies to the actual implementation before changing production systems.",
                    ],
                )
            )

        recommendations.sort(
            key=lambda item: (
                {
                    "critical": 0,
                    "high": 1,
                    "medium": 2,
                    "low": 3,
                    "informational": 4,
                }[item.priority],
                item.finding_id,
            )
        )

        if recommendations:
            summary = (
                f"Generated {len(recommendations)} remediation "
                f"recommendation(s) for {endpoint}. "
                "Review and validate each recommendation before "
                "implementing changes."
            )
        else:
            summary = (
                f"No remediation recommendations were generated for "
                f"{endpoint} because no supported security findings "
                "were available."
            )

        return RemediationPlan(
            path=reasoning.path,
            method=reasoning.method,
            endpoint_priority_score=priority_score,
            endpoint_priority_level=priority_level,
            total_recommendations=len(recommendations),
            recommendations=recommendations,
            summary=summary,
            limitations=[
                "Remediation guidance is deterministic and category-based.",
                "Recommendations are not proof that the endpoint is vulnerable.",
                "Implementation details must be reviewed against the actual application architecture.",
                "SHAP-only recommendations are investigation guidance, not automatic security fixes.",
                "No remediation is automatically applied to the target application.",
            ],
        )
