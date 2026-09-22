from typing import Final


GRAPH_FEATURE_NAMES: Final[tuple[str, ...]] = (
    "objects_with_full_operation_surface",
    "objects_with_mutation_without_read",
    "objects_with_delete_without_read",
    "objects_with_write_without_read",
    "objects_with_multiple_mutation_types",
    "objects_with_write_and_delete_without_read",
)


GRAPH_FEATURE_COUNT: Final[int] = len(GRAPH_FEATURE_NAMES)
