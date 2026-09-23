from pydantic import BaseModel

from ai.risk_prediction.evidence import SecurityEvidence


class EvidenceEvaluation(BaseModel):
    path: str
    method: str
    predicted_label: str | None = None
    has_security_evidence: bool
    vulnerability_types: list[str]


def evaluate_against_evidence(
    *,
    path: str,
    method: str,
    evidence: list[SecurityEvidence],
    predicted_label: str | None = None,
) -> EvidenceEvaluation:
    matches = [
        item
        for item in evidence
        if item.path == path and item.method.upper() == method.upper()
    ]

    return EvidenceEvaluation(
        path=path,
        method=method.upper(),
        predicted_label=predicted_label,
        has_security_evidence=bool(matches),
        vulnerability_types=[
            item.vulnerability_type
            for item in matches
        ],
    )
