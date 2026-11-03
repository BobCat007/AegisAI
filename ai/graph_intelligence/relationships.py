from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, Field

from ai.graph_intelligence.schema_resolver import OpenAPISchemaResolver


class ResourceRelationship(BaseModel):
    """A structurally inferred relationship between API resources."""

    source_resource: str
    target_resource: str
    relationship_type: str
    evidence_source: str
    evidence: str
    confidence: float = Field(ge=0.0, le=1.0)


class ResourceRelationshipGraph(BaseModel):
    """Relationship graph inferred from an OpenAPI specification."""

    relationships: list[ResourceRelationship] = Field(default_factory=list)
    unresolved_references: list[str] = Field(default_factory=list)
    circular_references: list[str] = Field(default_factory=list)
    truncated: bool = False


class ResourceRelationshipExtractor:
    """
    Infer resource relationships from paths and OpenAPI schemas.

    Relationships describe API structure only. They do not establish
    authorization behavior or prove an exploitable vulnerability.
    """

    IDENTIFIER_SUFFIXES = ("uuid", "ids", "id", "key")

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
        self.resolver = OpenAPISchemaResolver(
            spec,
            max_depth=max_depth,
            max_nodes=max_nodes,
        )
        self.relationships: list[ResourceRelationship] = []
        self._relationship_keys: set[tuple[str, str, str, str]] = set()
        self._unresolved: list[str] = []
        self._circular: list[str] = []
        self._truncated = False
        self._resolver_truncated = False
        self._nodes_visited = 0
        self._known_resources: set[str] = set()

    def extract(self) -> ResourceRelationshipGraph:
        self._extract_path_relationships()
        self._extract_component_relationships()

        return ResourceRelationshipGraph(
            relationships=self.relationships,
            unresolved_references=self._unresolved,
            circular_references=self._circular,
            truncated=self._truncated or self._resolver_truncated,
        )

    def _extract_path_relationships(self) -> None:
        paths = self.spec.get("paths", {})
        if not isinstance(paths, dict):
            return

        for path in paths:
            if not isinstance(path, str):
                continue
            segments = re.findall(r"\{([^{}]+)\}", path)
            if len(segments) < 2:
                continue

            resource_names = self._resource_names_from_path(path)
            for index in range(len(resource_names) - 1):
                source = resource_names[index]
                target = resource_names[index + 1]
                if source == target:
                    continue
                self._add_relationship(
                    source=source,
                    target=target,
                    relationship_type="nested_resource",
                    evidence_source="path",
                    evidence=path,
                    confidence=0.95,
                )

    @classmethod
    def _resource_names_from_path(cls, path: str) -> list[str]:
        segments = [
            segment
            for segment in path.strip("/").split("/")
            if segment
        ]
        resources: list[str] = []

        for segment in segments:
            if segment.startswith("{") and segment.endswith("}"):
                continue
            normalized = cls._normalize_resource_name(segment)
            if normalized and (not resources or resources[-1] != normalized):
                resources.append(normalized)

        return resources

    def _extract_component_relationships(self) -> None:
        components = self.spec.get("components", {})
        schemas = (
            components.get("schemas", {})
            if isinstance(components, dict)
            else {}
        )
        if not isinstance(schemas, dict):
            return

        self._known_resources = {
            self._normalize_resource_name(name)
            for name in schemas
            if isinstance(name, str)
        }

        for resource_name, schema in schemas.items():
            if self._truncated:
                break
            if not isinstance(resource_name, str):
                continue

            # The resolver is used for bounded reference diagnostics. The
            # original schema is walked separately to preserve exact evidence
            # locations for relationships.
            result = self.resolver.resolve(schema)
            self._merge_diagnostics(result)

            self._walk_schema(
                source_resource=self._normalize_resource_name(resource_name),
                schema=schema,
                evidence_prefix=f"components.schemas.{resource_name}",
                depth=0,
            )

    def _consume_node(self, depth: int) -> bool:
        if depth > self.max_depth or self._nodes_visited >= self.max_nodes:
            self._truncated = True
            return False
        self._nodes_visited += 1
        return True

    def _walk_schema(
        self,
        source_resource: str,
        schema: Any,
        evidence_prefix: str,
        depth: int,
    ) -> None:
        if self._truncated or not self._consume_node(depth):
            return

        if isinstance(schema, list):
            for index, item in enumerate(schema):
                if self._truncated:
                    break
                self._walk_schema(
                    source_resource,
                    item,
                    f"{evidence_prefix}[{index}]",
                    depth + 1,
                )
            return

        if not isinstance(schema, dict):
            return

        direct_reference = schema.get("$ref")
        if isinstance(direct_reference, str):
            target = self._resource_from_reference(direct_reference)
            if (
                target
                and target in self._known_resources
                and target != source_resource
            ):
                self._add_relationship(
                    source=source_resource,
                    target=target,
                    relationship_type="schema_reference",
                    evidence_source="schema_reference",
                    evidence=evidence_prefix,
                    confidence=0.95,
                )

        properties = schema.get("properties", {})
        if isinstance(properties, dict):
            for property_name, property_schema in properties.items():
                if self._truncated:
                    break
                property_path = (
                    f"{evidence_prefix}.properties.{property_name}"
                )
                self._extract_property_relationship(
                    source_resource,
                    property_name,
                    property_schema,
                    property_path,
                )
                self._walk_schema(
                    source_resource,
                    property_schema,
                    property_path,
                    depth + 1,
                )

        if self._truncated:
            return

        items = schema.get("items")
        if isinstance(items, (dict, list)):
            self._walk_schema(
                source_resource,
                items,
                f"{evidence_prefix}.items",
                depth + 1,
            )

        for composition in ("allOf", "oneOf", "anyOf"):
            if self._truncated:
                break
            members = schema.get(composition, [])
            if isinstance(members, list):
                for index, member in enumerate(members):
                    if self._truncated:
                        break
                    self._walk_schema(
                        source_resource,
                        member,
                        f"{evidence_prefix}.{composition}[{index}]",
                        depth + 1,
                    )

    def _extract_property_relationship(
        self,
        source_resource: str,
        property_name: str,
        property_schema: Any,
        evidence: str,
    ) -> None:
        if not isinstance(property_schema, dict):
            return

        reference = property_schema.get("$ref")
        if isinstance(reference, str):
            target = self._resource_from_reference(reference)
            if (
                target
                and target in self._known_resources
                and target != source_resource
            ):
                self._add_relationship(
                    source=source_resource,
                    target=target,
                    relationship_type="schema_reference",
                    evidence_source="schema_reference",
                    evidence=evidence,
                    confidence=0.95,
                )
                return

        if not property_name.lower().endswith(self.IDENTIFIER_SUFFIXES):
            return

        target = self._resource_from_identifier(property_name)
        # Identifier suffixes are weak evidence. Only infer a relationship
        # when the target is independently represented by a component schema.
        if (
            target
            and target in self._known_resources
            and target != source_resource
        ):
            self._add_relationship(
                source=source_resource,
                target=target,
                relationship_type="identifier_reference",
                evidence_source="identifier_property",
                evidence=evidence,
                confidence=0.75,
            )

    @classmethod
    def _resource_from_reference(cls, reference: str) -> str | None:
        prefix = "#/components/schemas/"
        if not reference.startswith(prefix):
            return None

        name = reference[len(prefix):].split("/")[0]
        name = name.replace("~1", "/").replace("~0", "~")
        return cls._normalize_resource_name(name)

    @classmethod
    def _resource_from_identifier(cls, property_name: str) -> str | None:
        normalized = property_name.lower()
        for suffix in cls.IDENTIFIER_SUFFIXES:
            if normalized.endswith(suffix):
                normalized = normalized[:-len(suffix)]
                break

        normalized = normalized.rstrip("_-")
        if not normalized:
            return None
        return cls._normalize_resource_name(normalized)

    @staticmethod
    def _normalize_resource_name(name: str) -> str:
        """Normalize common resource plurals without damaging singulars."""
        name = re.sub(r"(?<!^)(?=[A-Z])", "_", name)
        normalized = name.lower().strip("_")
        if not normalized:
            return ""

        # Common English plural forms. Order matters: "addresses" must
        # become "address", while singular "address" must remain unchanged.
        if normalized.endswith("ies") and len(normalized) > 3:
            return normalized[:-3] + "y"
        if normalized.endswith(("sses", "shes", "ches", "xes", "zes")):
            return normalized[:-2]
        if normalized.endswith("uses") and len(normalized) > 4:
            return normalized[:-2]
        if (
            normalized.endswith("s")
            and not normalized.endswith(("ss", "us", "is"))
            and len(normalized) > 1
        ):
            return normalized[:-1]
        return normalized

    def _add_relationship(
        self,
        source: str,
        target: str,
        relationship_type: str,
        evidence_source: str,
        evidence: str,
        confidence: float,
    ) -> None:
        key = (source, target, relationship_type, evidence)
        if key in self._relationship_keys:
            return
        self._relationship_keys.add(key)
        self.relationships.append(
            ResourceRelationship(
                source_resource=source,
                target_resource=target,
                relationship_type=relationship_type,
                evidence_source=evidence_source,
                evidence=evidence,
                confidence=confidence,
            )
        )

    def _merge_diagnostics(self, result: Any) -> None:
        for reference in result.unresolved_references:
            if reference not in self._unresolved:
                self._unresolved.append(reference)
        for reference in result.circular_references:
            if reference not in self._circular:
                self._circular.append(reference)
        self._resolver_truncated = (
            self._resolver_truncated or result.truncated
        )


def extract_resource_relationships(
    spec: dict[str, Any],
    max_depth: int = 32,
    max_nodes: int = 10000,
) -> ResourceRelationshipGraph:
    """Convenience function for resource relationship extraction."""
    return ResourceRelationshipExtractor(
        spec,
        max_depth=max_depth,
        max_nodes=max_nodes,
    ).extract()
