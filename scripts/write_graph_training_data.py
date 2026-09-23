import csv
from pathlib import Path

from ai.security_context_schema import SECURITY_CONTEXT_FEATURE_NAMES
from scripts.generate_training_data import generate_endpoint_templates
from scripts.graph_training_data import build_graph_training_samples


PROJECT_ROOT = Path(__file__).resolve().parent.parent

OUTPUT_PATH = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "api_graph_training_data.csv"
)


def write_graph_training_dataset() -> Path:
    """
    Generate and write the graph-aware API security training dataset.

    Each row contains:

        31 security-context features
        risk_label
        graph_context_score

    The graph training sample generator owns the complete
    sample contract, including the contextual risk score.
    """
    endpoints = generate_endpoint_templates()
    samples = build_graph_training_samples(endpoints)

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT_PATH.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as csv_file:
        writer = csv.writer(csv_file)

        writer.writerow(
            [
                *SECURITY_CONTEXT_FEATURE_NAMES,
                "risk_label",
                "graph_context_score",
            ]
        )

        for feature_vector, risk_label, graph_context_score in samples:
            writer.writerow(
                [
                    *feature_vector,
                    risk_label,
                    graph_context_score,
                ]
            )

    return OUTPUT_PATH


def main() -> None:
    output_path = write_graph_training_dataset()

    print(f"Graph training dataset written to: {output_path}")


if __name__ == "__main__":
    main()
