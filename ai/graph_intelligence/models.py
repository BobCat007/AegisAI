from pydantic import BaseModel, Field


class APIObjectNode(BaseModel):
    """
    Represents an API object identified by a path template.
    """

    path_template: str
    object_identifier_names: list[str] = Field(
        default_factory=list
    )
    target_method: str | None = None


class APIOperationEdge(BaseModel):
    """
    Represents an HTTP operation exposed against an API object.
    """

    path_template: str
    method: str


class APISecurityGraph(BaseModel):
    """
    In-memory representation of API object-operation relationships.
    """

    objects: list[APIObjectNode] = Field(
        default_factory=list
    )

    operations: list[APIOperationEdge] = Field(
        default_factory=list
    )
