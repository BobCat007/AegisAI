from typing import Final


FEATURE_NAMES: Final[tuple[str, ...]] = (
    "is_authenticated",
    "is_destructive",
    "has_path_parameters",
    "is_authentication_endpoint",
    "has_sensitive_parameters",
    "parameter_count",
    "path_depth",
    "has_request_body",
    "path_parameter_count",
    "query_parameter_count",
    "header_parameter_count",
    "request_body_property_count",
    "request_body_required_property_count",
    "request_body_max_depth",
    "has_response_body",
    "response_body_property_count",
    "response_body_max_depth",
    "method_get",
    "method_post",
    "method_put",
    "method_patch",
    "method_delete",
    "is_admin_context",
    "has_user_ownership_context",
    "has_other_user_context",
)


FEATURE_TYPES: Final[dict[str, str]] = {
    "is_authenticated": "binary",
    "is_destructive": "binary",
    "has_path_parameters": "binary",
    "is_authentication_endpoint": "binary",
    "has_sensitive_parameters": "binary",
    "parameter_count": "count",
    "path_depth": "count",
    "has_request_body": "binary",
    "path_parameter_count": "count",
    "query_parameter_count": "count",
    "header_parameter_count": "count",
    "request_body_property_count": "count",
    "request_body_required_property_count": "count",
    "request_body_max_depth": "count",
    "has_response_body": "binary",
    "response_body_property_count": "count",
    "response_body_max_depth": "count",
    "method_get": "binary",
    "method_post": "binary",
    "method_put": "binary",
    "method_patch": "binary",
    "method_delete": "binary",
    "is_admin_context": "binary",
    "has_user_ownership_context": "binary",
    "has_other_user_context": "binary",
}


FEATURE_DEFINITIONS: Final[tuple[str, ...]] = FEATURE_NAMES


FEATURE_COUNT: Final[int] = len(FEATURE_NAMES)
