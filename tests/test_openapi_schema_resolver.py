from ai.graph_intelligence.schema_resolver import (
    OpenAPISchemaResolver,
    resolve_openapi_schema,
)


def test_resolves_local_schema_reference():
    spec = {
        "components": {
            "schemas": {
                "User": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "integer"},
                        "username": {"type": "string"},
                    },
                }
            }
        }
    }

    result = resolve_openapi_schema(
        spec,
        {"$ref": "#/components/schemas/User"},
    )

    assert result.schema["type"] == "object"
    assert result.schema["properties"]["id"]["type"] == "integer"
    assert result.schema["properties"]["username"]["type"] == "string"
    assert result.unresolved_references == []
    assert result.circular_references == []
    assert result.truncated is False


def test_resolves_nested_references():
    spec = {
        "components": {
            "schemas": {
                "Address": {
                    "type": "object",
                    "properties": {
                        "city": {"type": "string"},
                    },
                },
                "User": {
                    "type": "object",
                    "properties": {
                        "address": {
                            "$ref": "#/components/schemas/Address"
                        }
                    },
                },
            }
        }
    }

    result = resolve_openapi_schema(
        spec,
        {"$ref": "#/components/schemas/User"},
    )

    address = result.schema["properties"]["address"]

    assert address["type"] == "object"
    assert address["properties"]["city"]["type"] == "string"
    assert result.unresolved_references == []


def test_resolves_references_inside_array_items():
    spec = {
        "components": {
            "schemas": {
                "Order": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "integer"},
                    },
                }
            }
        }
    }

    result = resolve_openapi_schema(
        spec,
        {
            "type": "array",
            "items": {
                "$ref": "#/components/schemas/Order"
            },
        },
    )

    item_schema = result.schema["items"]

    assert item_schema["type"] == "object"
    assert item_schema["properties"]["id"]["type"] == "integer"


def test_detects_circular_references():
    spec = {
        "components": {
            "schemas": {
                "User": {
                    "type": "object",
                    "properties": {
                        "manager": {
                            "$ref": "#/components/schemas/User"
                        }
                    },
                }
            }
        }
    }

    result = resolve_openapi_schema(
        spec,
        {"$ref": "#/components/schemas/User"},
    )

    assert result.schema["type"] == "object"
    assert (
        result.schema["properties"]["manager"]["$ref"]
        == "#/components/schemas/User"
    )
    assert result.circular_references == [
        "#/components/schemas/User"
    ]
    assert result.unresolved_references == []


def test_reports_missing_local_reference():
    spec = {"components": {"schemas": {}}}

    result = resolve_openapi_schema(
        spec,
        {"$ref": "#/components/schemas/Unknown"},
    )

    assert result.schema == {
        "$ref": "#/components/schemas/Unknown"
    }
    assert result.unresolved_references == [
        "#/components/schemas/Unknown"
    ]


def test_does_not_fetch_external_references():
    spec = {"components": {"schemas": {}}}
    external_reference = "https://example.com/schemas/User.json"

    result = resolve_openapi_schema(
        spec,
        {"$ref": external_reference},
    )

    assert result.schema["$ref"] == external_reference
    assert result.unresolved_references == [external_reference]


def test_supports_json_pointer_escaping():
    spec = {
        "components": {
            "schemas": {
                "User/Profile": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                    },
                }
            }
        }
    }

    result = resolve_openapi_schema(
        spec,
        {"$ref": "#/components/schemas/User~1Profile"},
    )

    assert result.schema["type"] == "object"
    assert result.schema["properties"]["name"]["type"] == "string"
    assert result.unresolved_references == []


def test_preserves_reference_siblings():
    spec = {
        "components": {
            "schemas": {
                "User": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "integer"},
                    },
                }
            }
        }
    }

    result = resolve_openapi_schema(
        spec,
        {
            "$ref": "#/components/schemas/User",
            "description": "A user resource",
        },
    )

    assert result.schema["properties"]["id"]["type"] == "integer"
    assert result.schema["description"] == "A user resource"


def test_enforces_maximum_depth():
    spec = {
        "components": {
            "schemas": {
                "Level3": {"type": "string"},
                "Level2": {
                    "properties": {
                        "child": {
                            "$ref": "#/components/schemas/Level3"
                        }
                    }
                },
                "Level1": {
                    "properties": {
                        "child": {
                            "$ref": "#/components/schemas/Level2"
                        }
                    }
                },
            }
        }
    }

    resolver = OpenAPISchemaResolver(spec, max_depth=1)

    result = resolver.resolve(
        {"$ref": "#/components/schemas/Level1"}
    )

    assert result.truncated is True


def test_enforces_node_limit():
    spec = {}
    resolver = OpenAPISchemaResolver(spec, max_nodes=2)

    result = resolver.resolve(
        {
            "type": "object",
            "properties": {
                "first": {"type": "string"},
                "second": {"type": "integer"},
            },
        }
    )

    assert result.truncated is True


def test_does_not_mutate_original_spec():
    spec = {
        "components": {
            "schemas": {
                "User": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "integer"},
                    },
                }
            }
        }
    }

    original = {
        "$ref": "#/components/schemas/User"
    }

    resolve_openapi_schema(spec, original)

    assert original == {
        "$ref": "#/components/schemas/User"
    }
    assert "$ref" in spec["components"]["schemas"]["User"] or (
        "properties" in spec["components"]["schemas"]["User"]
    )
