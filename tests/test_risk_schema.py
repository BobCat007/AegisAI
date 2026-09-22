from risk_engine.schema import (
    FEATURE_DEFINITIONS,
    FEATURE_NAMES,
    FEATURE_TYPES,
)


def test_feature_schema_contains_expected_number_of_features():
    assert len(FEATURE_DEFINITIONS) == 22
    assert len(FEATURE_NAMES) == 22


def test_feature_names_are_unique():
    assert len(FEATURE_NAMES) == len(set(FEATURE_NAMES))


def test_feature_schema_order():
    assert FEATURE_NAMES == [
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
    ]


def test_feature_types():
    assert FEATURE_TYPES["is_authenticated"] == "binary"
    assert FEATURE_TYPES["is_destructive"] == "binary"
    assert FEATURE_TYPES["parameter_count"] == "count"
    assert FEATURE_TYPES["path_depth"] == "count"
    assert FEATURE_TYPES["request_body_max_depth"] == "count"
    assert FEATURE_TYPES["response_body_property_count"] == "count"
    assert FEATURE_TYPES["response_body_max_depth"] == "count"
    assert FEATURE_TYPES["method_delete"] == "binary"
