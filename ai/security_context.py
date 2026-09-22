from pydantic import BaseModel, Field


class APISecurityContext(BaseModel):
    """
    Combined security intelligence for an API.

    Endpoint-level and graph-level features remain separate
    so each intelligence layer can evolve independently.
    """

    endpoint_features: list[float] = Field(
        default_factory=list
    )

    graph_features: dict[str, int] = Field(
        default_factory=dict
    )
