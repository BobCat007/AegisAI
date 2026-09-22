from dataclasses import dataclass


@dataclass(frozen=True)
class FeatureDefinition:
    """
    Metadata describing one ML-ready API security feature.
    """

    name: str
    description: str
    feature_type: str


FEATURE_DEFINITIONS = [
    FeatureDefinition(
        name="is_authenticated",
        description="Whether the API endpoint requires authentication.",
        feature_type="binary",
    ),
    FeatureDefinition(
        name="is_destructive",
        description="Whether the endpoint performs a destructive operation.",
        feature_type="binary",
    ),
    FeatureDefinition(
        name="has_path_parameters",
        description="Whether the endpoint contains object identifiers in its path.",
        feature_type="binary",
    ),
    FeatureDefinition(
        name="is_authentication_endpoint",
        description="Whether the endpoint is related to authentication.",
        feature_type="binary",
    ),
    FeatureDefinition(
        name="has_sensitive_parameters",
        description="Whether sensitive parameter names are present.",
        feature_type="binary",
    ),
    FeatureDefinition(
        name="parameter_count",
        description="Total number of API parameters.",
        feature_type="count",
    ),
    FeatureDefinition(
        name="path_depth",
        description="Number of meaningful path segments.",
        feature_type="count",
    ),
    FeatureDefinition(
        name="has_request_body",
        description="Whether the endpoint accepts a request body.",
        feature_type="binary",
    ),
    FeatureDefinition(
        name="path_parameter_count",
        description="Number of path parameters.",
        feature_type="count",
    ),
    FeatureDefinition(
        name="query_parameter_count",
        description="Number of query parameters.",
        feature_type="count",
    ),
    FeatureDefinition(
        name="header_parameter_count",
        description="Number of header parameters.",
        feature_type="count",
    ),
    FeatureDefinition(
        name="request_body_property_count",
        description="Number of top-level request body properties.",
        feature_type="count",
    ),
    FeatureDefinition(
        name="request_body_required_property_count",
        description="Number of required request body properties.",
        feature_type="count",
    ),
    FeatureDefinition(
        name="request_body_max_depth",
        description="Maximum nesting depth of the request body schema.",
        feature_type="count",
    ),
    FeatureDefinition(
        name="has_response_body",
        description="Whether the endpoint defines a response body.",
        feature_type="binary",
    ),
    FeatureDefinition(
        name="response_body_property_count",
        description="Number of top-level response body properties.",
        feature_type="count",
    ),
    FeatureDefinition(
        name="response_body_max_depth",
        description="Maximum nesting depth of the response body schema.",
        feature_type="count",
    ),
    FeatureDefinition(
        name="method_get",
        description="Whether the endpoint uses HTTP GET.",
        feature_type="binary",
    ),
    FeatureDefinition(
        name="method_post",
        description="Whether the endpoint uses HTTP POST.",
        feature_type="binary",
    ),
    FeatureDefinition(
        name="method_put",
        description="Whether the endpoint uses HTTP PUT.",
        feature_type="binary",
    ),
    FeatureDefinition(
        name="method_patch",
        description="Whether the endpoint uses HTTP PATCH.",
        feature_type="binary",
    ),
    FeatureDefinition(
        name="method_delete",
        description="Whether the endpoint uses HTTP DELETE.",
        feature_type="binary",
    ),
]


FEATURE_NAMES = [
    feature.name
    for feature in FEATURE_DEFINITIONS
]


FEATURE_TYPES = {
    feature.name: feature.feature_type
    for feature in FEATURE_DEFINITIONS
}
