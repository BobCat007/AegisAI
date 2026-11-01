from types import SimpleNamespace

import pytest

from ai.graph_intelligence.explanation_mapper import (
    GraphExplanationMapper,
)
from api_discovery.models import APIObjectOperationSurface


@pytest.fixture
def mapper():
    return GraphExplanationMapper()


@pytest.fixture
def surfaces():
    return [
        APIObjectOperationSurface(
            path_template="/users/{user_id}",
            object_identifier_names=["user_id"],
            operations=["GET", "POST", "DELETE"],
        ),
        APIObjectOperationSurface(
            path_template="/orders/{order_id}",
            object_identifier_names=["order_id"],
            operations=["POST"],
        ),
        APIObjectOperationSurface(
            path_template="/files/{file_id}",
            object_identifier_names=["file_id"],
            operations=["DELETE"],
        ),
        APIObjectOperationSurface(
            path_template="/products/{product_id}",
            object_identifier_names=["product_id"],
            operations=["PUT"],
        ),
        APIObjectOperationSurface(
            path_template="/accounts/{account_id}",
            object_identifier_names=["account_id"],
            operations=["POST", "PATCH"],
        ),
        APIObjectOperationSurface(
            path_template="/records/{record_id}",
            object_identifier_names=["record_id"],
            operations=["POST", "DELETE"],
        ),
        APIObjectOperationSurface(
            path_template="/health",
            object_identifier_names=[],
            operations=["GET"],
        ),
    ]


def test_full_operation_surface_mapping(mapper, surfaces):
    result = mapper.map_feature(
        "objects_with_full_operation_surface", 1, 0.5, surfaces
    )

    assert result["matched_object_count"] == 1
    assert result["count_matches"] is True
    assert result["scope"] == "assessment_graph"
    assert result["evidence"][0]["path_template"] == "/users/{user_id}"
    assert result["evidence"][0]["object_identifier_names"] == ["user_id"]


def test_mutation_without_read_mapping(mapper, surfaces):
    result = mapper.map_feature(
        "objects_with_mutation_without_read", 5, 0.3, surfaces
    )

    paths = {item["path_template"] for item in result["evidence"]}

    assert result["matched_object_count"] == 5
    assert result["count_matches"] is True
    assert paths == {
        "/orders/{order_id}",
        "/files/{file_id}",
        "/products/{product_id}",
        "/accounts/{account_id}",
        "/records/{record_id}",
    }


def test_delete_without_read_mapping(mapper, surfaces):
    result = mapper.map_feature(
        "objects_with_delete_without_read", 2, 0.7, surfaces
    )

    paths = {item["path_template"] for item in result["evidence"]}

    assert result["matched_object_count"] == 2
    assert result["count_matches"] is True
    assert paths == {
        "/files/{file_id}",
        "/records/{record_id}",
    }


def test_write_without_read_mapping(mapper, surfaces):
    result = mapper.map_feature(
        "objects_with_write_without_read", 4, 0.2, surfaces
    )

    paths = {item["path_template"] for item in result["evidence"]}

    assert result["matched_object_count"] == 4
    assert result["count_matches"] is True
    assert paths == {
        "/orders/{order_id}",
        "/products/{product_id}",
        "/accounts/{account_id}",
        "/records/{record_id}",
    }


def test_multiple_mutation_types_mapping(mapper, surfaces):
    result = mapper.map_feature(
        "objects_with_multiple_mutation_types", 3, 0.4, surfaces
    )

    paths = {item["path_template"] for item in result["evidence"]}

    assert result["matched_object_count"] == 3
    assert result["count_matches"] is True
    assert paths == {
        "/users/{user_id}",
        "/accounts/{account_id}",
        "/records/{record_id}",
    }


def test_write_and_delete_without_read_mapping(mapper, surfaces):
    result = mapper.map_feature(
        "objects_with_write_and_delete_without_read", 1, 0.6, surfaces
    )

    assert result["matched_object_count"] == 1
    assert result["count_matches"] is True
    assert result["evidence"][0]["path_template"] == "/records/{record_id}"


def test_positive_shap_value_increases_class_score(mapper, surfaces):
    result = mapper.map_feature(
        "objects_with_delete_without_read", 2, 0.5, surfaces
    )

    assert result["direction"] == "increases_class_score"


def test_negative_shap_value_decreases_class_score(mapper, surfaces):
    result = mapper.map_feature(
        "objects_with_delete_without_read", 2, -0.5, surfaces
    )

    assert result["direction"] == "decreases_class_score"


def test_zero_shap_value_has_no_effect(mapper, surfaces):
    result = mapper.map_feature(
        "objects_with_delete_without_read", 2, 0, surfaces
    )

    assert result["direction"] == "no_effect"


def test_empty_surfaces_return_empty_evidence(mapper):
    result = mapper.map_feature(
        "objects_with_delete_without_read", 0, 0.2, []
    )

    assert result["matched_object_count"] == 0
    assert result["count_matches"] is True
    assert result["evidence"] == []


def test_count_mismatch_is_reported(mapper, surfaces):
    result = mapper.map_feature(
        "objects_with_delete_without_read", 99, 0.2, surfaces
    )

    assert result["matched_object_count"] == 2
    assert result["count_matches"] is False


def test_non_graph_contributions_are_ignored(mapper, surfaces):
    contributions = [
        SimpleNamespace(
            feature_name="target_has_delete_without_read",
            feature_value=1,
            shap_value=0.5,
        ),
        SimpleNamespace(
            feature_name="objects_with_delete_without_read",
            feature_value=2,
            shap_value=0.7,
        ),
    ]

    results = mapper.map_contributions(contributions, surfaces)

    assert len(results) == 1
    assert results[0]["feature_name"] == "objects_with_delete_without_read"


def test_object_operations_are_normalized(mapper):
    surface = APIObjectOperationSurface(
        path_template="/items/{item_id}",
        object_identifier_names=["item_id"],
        operations=["post", "delete"],
    )

    result = mapper.map_feature(
        "objects_with_write_and_delete_without_read", 1, 0.4, [surface]
    )

    assert result["matched_object_count"] == 1
    assert result["evidence"][0]["operations"] == ["DELETE", "POST"]


def test_unknown_graph_feature_raises_error(mapper, surfaces):
    with pytest.raises(ValueError, match="Unsupported graph feature"):
        mapper.map_feature("unknown_graph_feature", 1, 0.5, surfaces)


@pytest.mark.parametrize(
    "feature_value,shap_value",
    [
        (float("nan"), 0.5),
        (float("inf"), 0.5),
        (1, float("nan")),
        (1, float("inf")),
    ],
)
def test_non_finite_values_are_rejected(
    mapper, surfaces, feature_value, shap_value
):
    with pytest.raises(ValueError):
        mapper.map_feature(
            "objects_with_delete_without_read",
            feature_value,
            shap_value,
            surfaces,
        )
