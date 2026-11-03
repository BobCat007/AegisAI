import json
from typing import Any

from ai.knowledge.models import KnowledgeDocument
from ai.knowledge.normalizer import (
    sanitize_text,
    sanitize_value,
    stable_document_id,
    to_plain_dict,
)


class SecurityKnowledgeBuilder:
    """Convert existing AegisAI outputs into deterministic knowledge records.

    Inputs may be Pydantic models or dictionaries. The builder deliberately
    does not infer confirmation from model scores, structural indicators, or
    the presence of remediation advice.
    """

    @staticmethod
    def _document(
        *,
        document_type: str,
        source: str,
        source_reference: str,
        title: Any,
        content: Any,
        severity: Any = None,
        priority: Any = None,
        confidence: Any = None,
        validation_status: Any = None,
        confirmed: bool = False,
        metadata: dict[str, Any] | None = None,
    ) -> KnowledgeDocument:
        safe_source = sanitize_text(source)
        safe_reference = sanitize_text(source_reference)
        safe_metadata = sanitize_value(metadata or {})
        safe_confidence = confidence if isinstance(confidence, (int, float)) else None
        if safe_confidence is not None:
            safe_confidence = max(0.0, min(1.0, float(safe_confidence)))

        return KnowledgeDocument(
            document_id=stable_document_id(document_type, safe_source, safe_reference),
            document_type=document_type,
            title=sanitize_text(title or document_type.replace("_", " ").title()),
            content=sanitize_text(content),
            source=safe_source,
            source_reference=safe_reference,
            severity=sanitize_text(severity) if severity is not None else None,
            priority=sanitize_text(priority) if priority is not None else None,
            confidence=safe_confidence,
            validation_status=(
                sanitize_text(validation_status) if validation_status is not None else None
            ),
            confirmed=bool(confirmed),
            metadata=safe_metadata,
        )

    def from_reasoning(self, result: Any) -> list[KnowledgeDocument]:
        data = to_plain_dict(result)
        endpoint = f"{data.get('method', '')} {data.get('path', '')}".strip()
        documents = []
        for finding in data.get("findings", []):
            ref = str(finding.get("finding_id") or finding.get("category") or "finding")
            evidence = finding.get("evidence", [])
            details = [
                item.get("detail", "")
                for item in evidence
                if isinstance(item, dict)
            ]
            content = "\n".join([
                str(finding.get("explanation", "")),
                f"Endpoint: {endpoint}",
                "Evidence: " + "; ".join(map(str, details)),
                "Recommended validation: "
                + "; ".join(map(str, finding.get("recommended_validation", []))),
            ])
            is_runtime_validated = finding.get("validation_status") == "runtime_validated"
            explicitly_confirmed = data.get("vulnerabilities_confirmed") is True
            documents.append(self._document(
                document_type="reasoning_finding",
                source="ai.security_reasoning",
                source_reference=f"{endpoint}#{ref}",
                title=finding.get("title"),
                content=content,
                severity=finding.get("severity"),
                confidence=None,
                validation_status=finding.get("validation_status", "not_validated"),
                confirmed=explicitly_confirmed and is_runtime_validated,
                metadata={
                    "category": finding.get("category"),
                    "finding_id": ref,
                    "overall_assessment": data.get("overall_assessment"),
                    "limitations": data.get("limitations", []),
                },
            ))
        return documents

    def from_evidence_correlation(
        self, result: Any, source_reference: str
    ) -> list[KnowledgeDocument]:
        data = to_plain_dict(result)
        documents = []
        for group in data.get("groups", []):
            group_id = str(group.get("group_id", "group"))
            sources = group.get("evidence", [])
            details = [
                {
                    "source_id": item.get("source_id"),
                    "source_type": item.get("source_type"),
                    "scope": item.get("scope"),
                    "detail": item.get("detail"),
                    "reference": item.get("reference"),
                    "indicator": item.get("indicator"),
                    "direction": item.get("direction"),
                    "dependency_group": item.get("dependency_group"),
                }
                for item in sources
                if isinstance(item, dict)
            ]
            documents.append(self._document(
                document_type="evidence_source",
                source="ai.security_reasoning.correlation",
                source_reference=f"{source_reference}#{group_id}",
                title=f"Correlated evidence group {group_id}",
                content=(
                    f"Evidence group at scope {group.get('scope')}; "
                    f"{len(details)} source(s), "
                    f"{group.get('independent_source_count', 0)} independent source(s)."
                ),
                metadata={
                    "scope": group.get("scope"),
                    "reference": group.get("reference"),
                    "evidence": details,
                    "relationships": group.get("relationships", []),
                    "limitations": data.get("limitations", []),
                },
            ))
        return documents

    def from_remediation(self, plan: Any) -> list[KnowledgeDocument]:
        data = to_plain_dict(plan)
        endpoint = f"{data.get('method', '')} {data.get('path', '')}".strip()
        documents = []
        for item in data.get("recommendations", []):
            remediation_id = str(item.get("remediation_id", "remediation"))
            content = "\n".join([
                str(item.get("objective", "")),
                "Remediation steps: "
                + "; ".join(map(str, item.get("remediation_steps", []))),
                "Validation steps: "
                + "; ".join(map(str, item.get("validation_steps", []))),
                "Limitations: " + "; ".join(map(str, item.get("limitations", []))),
            ])
            documents.append(self._document(
                document_type="remediation",
                source="ai.security_reasoning.remediation",
                source_reference=f"{endpoint}#{remediation_id}",
                title=item.get("title"),
                content=content,
                priority=item.get("priority"),
                metadata={
                    "finding_id": item.get("finding_id"),
                    "category": item.get("category"),
                    "endpoint": item.get("endpoint"),
                    "evidence_references": item.get("evidence_references", []),
                    "evidence_sources": item.get("evidence_sources", []),
                    "plan_priority_score": data.get("endpoint_priority_score"),
                    "plan_priority_level": data.get("endpoint_priority_level"),
                },
            ))
        return documents

    def from_authorization_finding(
        self, finding: Any, source_reference: str
    ) -> KnowledgeDocument:
        data = to_plain_dict(finding)
        safe_evidence = sanitize_value(data.get("evidence", {}))
        content = "\n".join([
            str(data.get("description", "")),
            f"Operation: {data.get('operation', '')}",
            f"Identity: {data.get('identity') or 'not supplied'}",
            f"Resource: {data.get('resource_id') or 'not supplied'}",
            "Evidence: " + json.dumps(safe_evidence, sort_keys=True, default=str),
        ])
        return self._document(
            document_type="authorization_finding",
            source="ai.authorization",
            source_reference=source_reference,
            title=data.get("title"),
            content=content,
            severity=data.get("severity"),
            confidence=data.get("confidence"),
            validation_status=data.get("status"),
            confirmed=data.get("status") == "confirmed",
            metadata={
                "finding_type": data.get("finding_type"),
                "status": data.get("status"),
                "operation": data.get("operation"),
                "identity": data.get("identity"),
                "resource_id": data.get("resource_id"),
                "evidence": safe_evidence,
            },
        )

    def from_behavioral_result(
        self, result: Any, source_reference: str
    ) -> KnowledgeDocument:
        data = to_plain_dict(result)
        anomalous = data.get("classification") == "anomalous"
        signals = sanitize_value(data.get("signals", []))
        return self._document(
            document_type="behavioral_anomaly",
            source="ai.behavioral_intelligence",
            source_reference=source_reference,
            title=(
                f"Behavioral {data.get('classification', 'assessment')} — "
                f"{data.get('method', '')} {data.get('endpoint_path', '')}"
            ).strip(),
            content=(
                f"Classification: {data.get('classification')}; "
                f"anomaly score: {data.get('anomaly_score')}. "
                f"Data origin: {data.get('data_origin')}. "
                f"Signals: {json.dumps(signals, sort_keys=True, default=str)}. "
                f"Limitations: {data.get('limitations', [])}"
            ),
            validation_status=(
                "runtime_observation"
                if data.get("data_origin") == "runtime"
                else "synthetic_observation"
            ),
            confirmed=False,
            metadata={
                "endpoint_path": data.get("endpoint_path"),
                "method": data.get("method"),
                "classification": data.get("classification"),
                "anomaly_score": data.get("anomaly_score"),
                "data_origin": data.get("data_origin"),
                "signals": signals,
                "anomalous_signal": anomalous,
            },
        )

    def from_attack_chain(self, chain: Any, source_reference: str) -> KnowledgeDocument:
        data = to_plain_dict(chain)
        resources = sanitize_value(data.get("resources", []))
        relationships = sanitize_value(data.get("relationships", []))
        evidence_sources = sanitize_value(data.get("evidence_sources", []))
        resource_path = " → ".join(map(str, resources))
        return self._document(
            document_type="attack_chain",
            source="ai.graph_intelligence.attack_chain",
            source_reference=source_reference,
            title="Inferred API resource path: " + resource_path,
            content=(
                f"Resources: {resource_path}. "
                f"Hops: {data.get('hop_count')}; "
                f"relationship confidence: {data.get('confidence')}. "
                f"Interpretation: {data.get('interpretation', 'Inferred structural path; not a confirmed exploit.')}"
            ),
            confidence=data.get("confidence"),
            validation_status="structurally_inferred",
            confirmed=False,
            metadata={
                "resources": resources,
                "hop_count": data.get("hop_count"),
                "evidence_sources": evidence_sources,
                "relationships": relationships,
                "score_is_exploit_probability": False,
            },
        )
