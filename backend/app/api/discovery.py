from typing import Any

from fastapi import APIRouter, HTTPException

from api_discovery.service import discover_api


router = APIRouter(
    prefix="/api/discovery",
    tags=["API Discovery"],
)


@router.post("/openapi")
def discover_openapi(spec: dict[str, Any]):
    """
    Discover API endpoints from an OpenAPI/Swagger specification.
    """

    try:
        inventory = discover_api(spec)

        return {
            "status": "success",
            "inventory": inventory.model_dump(),
        }

    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Unable to process OpenAPI specification: {exc}",
        ) from exc
