from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any


@dataclass
class SchemaResolution:
    """Resolved schema plus diagnostics collected during traversal."""

    schema: Any
    unresolved_references: list[str] = field(default_factory=list)
    circular_references: list[str] = field(default_factory=list)
    truncated: bool = False


class OpenAPISchemaResolver:
    """
    Safely resolve local OpenAPI JSON Pointer references.

    External references are deliberately not fetched. Unresolved and
    circular references remain as $ref objects in the returned schema.
    """

    def __init__(
        self,
        spec: dict[str, Any],
        max_depth: int = 32,
        max_nodes: int = 10000,
    ) -> None:
        if not isinstance(spec, dict):
            raise TypeError("OpenAPI specification must be a dictionary.")

        if max_depth < 1:
            raise ValueError("max_depth must be at least 1.")

        if max_nodes < 1:
            raise ValueError("max_nodes must be at least 1.")

        self.spec = spec
        self.max_depth = max_depth
        self.max_nodes = max_nodes

    def resolve(self, schema: Any) -> SchemaResolution:
        """Resolve references within a schema and return diagnostics."""

        state = {
            "visited_nodes": 0,
            "truncated": False,
            "unresolved": [],
            "circular": [],
        }

        resolved = self._resolve_node(
            node=schema,
            depth=0,
            active_references=(),
            state=state,
        )

        return SchemaResolution(
            schema=resolved,
            unresolved_references=state["unresolved"],
            circular_references=state["circular"],
            truncated=state["truncated"],
        )

    def resolve_reference(self, reference: str) -> SchemaResolution:
        """Resolve a reference string directly."""

        return self.resolve({"$ref": reference})

    def _resolve_node(
        self,
        node: Any,
        depth: int,
        active_references: tuple[str, ...],
        state: dict[str, Any],
    ) -> Any:
        if depth > self.max_depth:
            state["truncated"] = True
            return deepcopy(node)

        state["visited_nodes"] += 1

        if state["visited_nodes"] > self.max_nodes:
            state["truncated"] = True
            return deepcopy(node)

        if isinstance(node, list):
            return [
                self._resolve_node(
                    item,
                    depth + 1,
                    active_references,
                    state,
                )
                for item in node
            ]

        if not isinstance(node, dict):
            return deepcopy(node)

        reference = node.get("$ref")

        if isinstance(reference, str):
            resolved_reference = self._resolve_ref(
                reference=reference,
                depth=depth,
                active_references=active_references,
                siblings={
                    key: value
                    for key, value in node.items()
                    if key != "$ref"
                },
                state=state,
            )

            return resolved_reference

        return {
            key: self._resolve_node(
                value,
                depth + 1,
                active_references,
                state,
            )
            for key, value in node.items()
        }

    def _resolve_ref(
        self,
        reference: str,
        depth: int,
        active_references: tuple[str, ...],
        siblings: dict[str, Any],
        state: dict[str, Any],
    ) -> Any:
        if not reference.startswith("#/"):
            self._add_unique(state["unresolved"], reference)
            return self._preserve_reference(reference, siblings)

        if reference in active_references:
            self._add_unique(state["circular"], reference)
            return self._preserve_reference(reference, siblings)

        try:
            target = self._get_json_pointer(reference)
        except (KeyError, IndexError, TypeError, ValueError):
            self._add_unique(state["unresolved"], reference)
            return self._preserve_reference(reference, siblings)

        resolved_target = self._resolve_node(
            node=target,
            depth=depth + 1,
            active_references=active_references + (reference,),
            state=state,
        )

        if not isinstance(resolved_target, dict):
            if siblings:
                resolved_siblings = self._resolve_node(
                    siblings,
                    depth + 1,
                    active_references,
                    state,
                )
                return {
                    "allOf": [
                        resolved_target,
                        resolved_siblings,
                    ]
                }

            return resolved_target

        if not siblings:
            return resolved_target

        resolved_siblings = self._resolve_node(
            siblings,
            depth + 1,
            active_references,
            state,
        )

        return {
            **resolved_target,
            **resolved_siblings,
        }

    def _get_json_pointer(self, reference: str) -> Any:
        """Read a local JSON Pointer from the OpenAPI document."""

        if not reference.startswith("#/"):
            raise ValueError("Only local JSON Pointer references are supported.")

        pointer = reference[2:]
        current: Any = self.spec

        for raw_token in pointer.split("/"):
            token = raw_token.replace("~1", "/").replace("~0", "~")

            if isinstance(current, dict):
                current = current[token]
            elif isinstance(current, list):
                current = current[int(token)]
            else:
                raise TypeError(
                    f"Cannot traverse JSON Pointer token: {token}"
                )

        return current

    @staticmethod
    def _preserve_reference(
        reference: str,
        siblings: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "$ref": reference,
            **deepcopy(siblings),
        }

    @staticmethod
    def _add_unique(items: list[str], value: str) -> None:
        if value not in items:
            items.append(value)


def resolve_openapi_schema(
    spec: dict[str, Any],
    schema: Any,
    max_depth: int = 32,
    max_nodes: int = 10000,
) -> SchemaResolution:
    """Convenience function for resolving one schema."""

    resolver = OpenAPISchemaResolver(
        spec=spec,
        max_depth=max_depth,
        max_nodes=max_nodes,
    )

    return resolver.resolve(schema)
