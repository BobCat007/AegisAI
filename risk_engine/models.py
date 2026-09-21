from pydantic import BaseModel, Field


class RiskFactor(BaseModel):
    name: str
    weight: float
    triggered: bool


class RiskAssessment(BaseModel):
    score: float = Field(ge=0, le=100)
    severity: str
    reasons: list[str] = Field(default_factory=list)
    risk_factors: list[RiskFactor] = Field(default_factory=list)
