from typing import Any

from pydantic import BaseModel, Field


class SecurityClassification(BaseModel):
    is_authenticated: bool = False
    is_destructive: bool = False
    has_path_parameters: bool = False
    object_identifier_names: list[str] = Field(default_factory=list)
    object_access_pattern: str = "collection"
    is_authentication_endpoint: bool = False

    has_sensitive_parameters: bool = False
    sensitive_parameters: list[str] = Field(default_factory=list)

    has_sensitive_response_fields: bool = False
    sensitive_response_fields: list[str] = Field(default_factory=list)

    risk_indicators: list[str] = Field(default_factory=list)


class APIEndpoint(BaseModel):
    path: str
    method: str
    operation_category: str
    operation_id: str | None = None
    summary: str | None = None
    description: str | None = None
    tags: list[str] = Field(default_factory=list)
    parameters: list[dict[str, Any]] = Field(default_factory=list)
    request_body: dict[str, Any] | None = None
    responses: dict[str, Any] = Field(default_factory=dict)
    security: list[dict[str, Any]] = Field(default_factory=list)
    security_classification: SecurityClassification = Field(
        default_factory=SecurityClassification
    )


class APIObjectOperationSurface(BaseModel):
    path_template: str
    object_identifier_names: list[str] = Field(default_factory=list)
    operations: list[str] = Field(default_factory=list)
    target_method: str | None = None
    has_read_operation: bool = False
    has_write_operation: bool = False
    has_delete_operation: bool = False


class APIInventory(BaseModel):
    title: str
    version: str
    openapi_version: str
    total_endpoints: int
    endpoints: list[APIEndpoint]
    object_operation_surfaces: list[APIObjectOperationSurface] = Field(
        default_factory=list
    )
