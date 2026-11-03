from ai.graph_intelligence.relationships import (
    ResourceRelationshipExtractor,
    extract_resource_relationships,
)


def _schemas(**schemas):
    return {"components": {"schemas": schemas}}


def _relationships(result, relationship_type=None):
    if relationship_type is None:
        return result.relationships
    return [
        item for item in result.relationships
        if item.relationship_type == relationship_type
    ]


def test_extracts_nested_path_relationship():
    spec = {
        "paths": {
            "/users/{userId}/orders/{orderId}": {"get": {}}
        }
    }
    result = extract_resource_relationships(spec)
    assert any(
        item.source_resource == "user"
        and item.target_resource == "order"
        and item.relationship_type == "nested_resource"
        for item in result.relationships
    )


def test_extracts_schema_reference_relationship():
    spec = _schemas(
        User={
            "type": "object",
            "properties": {
                "orders": {
                    "type": "array",
                    "items": {"$ref": "#/components/schemas/Order"},
                }
            },
        },
        Order={"type": "object", "properties": {"id": {"type": "integer"}}},
    )
    result = extract_resource_relationships(spec)
    assert any(
        item.source_resource == "user"
        and item.target_resource == "order"
        and item.relationship_type == "schema_reference"
        for item in result.relationships
    )


def test_extracts_identifier_relationship_only_for_known_schema():
    spec = _schemas(
        Order={"type": "object", "properties": {"userId": {"type": "integer"}}},
        User={"type": "object"},
    )
    result = extract_resource_relationships(spec)
    assert any(
        item.source_resource == "order"
        and item.target_resource == "user"
        and item.relationship_type == "identifier_reference"
        for item in result.relationships
    )


def test_extracts_multiple_grounded_identifier_relationships():
    spec = _schemas(
        Order={
            "type": "object",
            "properties": {
                "userId": {"type": "integer"},
                "paymentId": {"type": "integer"},
            },
        },
        User={"type": "object"},
        Payment={"type": "object"},
    )
    result = extract_resource_relationships(spec)
    targets = {
        item.target_resource
        for item in _relationships(result, "identifier_reference")
    }
    assert targets == {"user", "payment"}


def test_does_not_infer_identifier_relationship_without_target_schema():
    spec = _schemas(
        Order={
            "type": "object",
            "properties": {
                "userId": {"type": "integer"},
                "paymentId": {"type": "integer"},
                "externalId": {"type": "string"},
                "transactionId": {"type": "string"},
            },
        }
    )
    assert extract_resource_relationships(spec).relationships == []


def test_deduplicates_identical_relationships():
    spec = _schemas(
        Order={"type": "object", "properties": {"userId": {"type": "integer"}}},
        User={"type": "object"},
    )
    result = extract_resource_relationships(spec)
    assert len(_relationships(result, "identifier_reference")) == 1


def test_reports_unresolved_schema_references():
    spec = _schemas(
        Order={
            "type": "object",
            "properties": {"user": {"$ref": "#/components/schemas/Missing"}},
        }
    )
    result = extract_resource_relationships(spec)
    assert "#/components/schemas/Missing" in result.unresolved_references
    assert result.relationships == []


def test_reports_circular_schema_references():
    spec = _schemas(
        User={
            "type": "object",
            "properties": {"manager": {"$ref": "#/components/schemas/User"}},
        }
    )
    result = extract_resource_relationships(spec)
    assert "#/components/schemas/User" in result.circular_references


def test_does_not_create_relationship_for_unrelated_schema():
    spec = _schemas(
        HealthStatus={
            "type": "object",
            "properties": {
                "status": {"type": "string"},
                "message": {"type": "string"},
            },
        }
    )
    assert extract_resource_relationships(spec).relationships == []


def test_relationship_confidence_is_bounded():
    spec = _schemas(
        Order={"type": "object", "properties": {"userId": {"type": "integer"}}},
        User={"type": "object"},
    )
    result = extract_resource_relationships(spec)
    assert all(0.0 <= item.confidence <= 1.0 for item in result.relationships)


def test_extractor_does_not_mutate_original_spec():
    spec = _schemas(
        Order={"type": "object", "properties": {"userId": {"type": "integer"}}},
        User={"type": "object"},
    )
    original = {
        "components": {
            "schemas": {
                "Order": {
                    "type": "object",
                    "properties": {"userId": {"type": "integer"}},
                },
                "User": {"type": "object"},
            }
        }
    }
    extract_resource_relationships(spec)
    assert spec == original


def test_empty_spec_returns_empty_graph():
    result = extract_resource_relationships({})
    assert result.relationships == []
    assert result.unresolved_references == []
    assert result.circular_references == []
    assert result.truncated is False


def test_resource_name_normalization_preserves_singular_words():
    normalize = ResourceRelationshipExtractor._normalize_resource_name
    assert normalize("status") == "status"
    assert normalize("address") == "address"
    assert normalize("HealthStatus") == "health_status"


def test_resource_name_normalization_handles_common_plurals():
    normalize = ResourceRelationshipExtractor._normalize_resource_name
    assert normalize("users") == "user"
    assert normalize("orders") == "order"
    assert normalize("categories") == "category"
    assert normalize("addresses") == "address"
    assert normalize("statuses") == "status"


def test_path_relationship_normalization_preserves_status_and_address():
    spec = {
        "paths": {
            "/statuses/{statusId}/addresses/{addressId}/orders/{orderId}": {
                "get": {}
            }
        }
    }
    result = extract_resource_relationships(spec)
    pairs = {
        (item.source_resource, item.target_resource)
        for item in _relationships(result, "nested_resource")
    }
    assert ("status", "address") in pairs
    assert ("address", "order") in pairs


def test_schema_reference_to_unknown_component_is_not_emitted():
    spec = _schemas(
        Order={
            "type": "object",
            "properties": {"user": {"$ref": "#/components/schemas/NotDefined"}},
        }
    )
    result = extract_resource_relationships(spec)
    assert result.relationships == []
    assert "#/components/schemas/NotDefined" in result.unresolved_references


def test_extractor_enforces_recursive_depth_limit():
    nested = {"type": "string"}
    for _ in range(8):
        nested = {"type": "object", "properties": {"child": nested}}
    spec = _schemas(Deep=nested)

    result = extract_resource_relationships(spec, max_depth=3)
    assert result.truncated is True


def test_extractor_enforces_global_node_limit():
    properties = {
        f"field{index}": {"type": "string"}
        for index in range(30)
    }
    spec = _schemas(Large={"type": "object", "properties": properties})

    result = extract_resource_relationships(spec, max_nodes=5)
    assert result.truncated is True


def test_extractor_stops_processing_later_schemas_after_budget_exhaustion():
    first = {
        "type": "object",
        "properties": {
            f"field{index}": {"type": "string"}
            for index in range(20)
        },
    }
    second = {
        "type": "object",
        "properties": {
            "userId": {"type": "integer"},
        },
    }
    spec = _schemas(First=first, Second=second, User={"type": "object"})

    result = extract_resource_relationships(spec, max_nodes=4)
    assert result.truncated is True
    assert result.relationships == []


def test_external_reference_is_not_fetched_or_inferred():
    spec = _schemas(
        Order={
            "type": "object",
            "properties": {
                "user": {"$ref": "https://example.com/User.json"},
            },
        }
    )
    result = extract_resource_relationships(spec)
    assert result.relationships == []
    assert "https://example.com/User.json" in result.unresolved_references


def test_identifier_target_matching_is_case_and_plural_normalized():
    spec = _schemas(
        Order={"type": "object", "properties": {"categoriesId": {"type": "integer"}}},
        Category={"type": "object"},
    )
    result = extract_resource_relationships(spec)
    assert any(
        item.target_resource == "category"
        and item.relationship_type == "identifier_reference"
        for item in result.relationships
    )


def test_invalid_limits_are_rejected():
    spec = {}
    for kwargs in ({"max_depth": 0}, {"max_nodes": 0}):
        try:
            ResourceRelationshipExtractor(spec, **kwargs)
        except ValueError:
            pass
        else:
            raise AssertionError("Expected ValueError for invalid traversal limit")
