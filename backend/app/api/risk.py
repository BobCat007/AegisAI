from fastapi import APIRouter

from api_discovery.models import APIEndpoint
from risk_engine.scorer import calculate_risk


router = APIRouter(
    prefix="/api/risk",
    tags=["Risk Engine"],
)


@router.post("/assess")
def assess_risk(endpoint: APIEndpoint):
    """
    Calculate the baseline security risk of an API endpoint.
    """

    assessment = calculate_risk(endpoint)

    return {
        "status": "success",
        "risk_assessment": assessment.model_dump(),
    }
