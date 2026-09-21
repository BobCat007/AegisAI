from typing import Any

from pydantic import BaseModel, Field


class APIEndpoint(BaseModel):
    path: str
    method: str
    operation_id: str | None = None
    summary: str | None = None
    description: str | None = None
    tags: list[str] = Field(default_factory=list)
    parameters: list[dict[str, Any]] = Field(default_factory=list)
    request_body: dict[str, Any] | None = None
    security: list[dict[str, Any]] = Field(default_factory=list)


class APIInventory(BaseModel):
    title: str
    version: str
    openapi_version: str
    total_endpoints: int
    endpoints: list[APIEndpoint]
