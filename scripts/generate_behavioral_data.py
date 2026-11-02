import csv
from pathlib import Path

from ai.behavioral_intelligence.synthetic import (
    generate_normal_observations,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]

OUTPUT_PATH = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "behavioral_baseline.csv"
)


def main() -> None:
    observations = generate_normal_observations(
        count=500,
        random_state=42,
    )

    OUTPUT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    rows = [
        observation.model_dump()
        for observation in observations
    ]

    with OUTPUT_PATH.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as csv_file:
        writer = csv.DictWriter(
            csv_file,
            fieldnames=list(rows[0].keys()),
        )

        writer.writeheader()
        writer.writerows(rows)

    print("Synthetic behavioral baseline generated.")
    print(f"Observations: {len(observations)}")
    print(f"Output: {OUTPUT_PATH}")
    print("Data origin: synthetic")


if __name__ == "__main__":
    main()
