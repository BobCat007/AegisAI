from pathlib import Path

import matplotlib.pyplot as plt


OUTPUT_DIR = Path("reports/graphs")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

labels = [
    "Low",
    "Medium",
    "High",
    "Critical",
]

sample_counts = [
    222,
    114,
    30,
    18,
]


plt.figure(figsize=(10, 6))

bars = plt.bar(
    labels,
    sample_counts,
)

plt.title(
    "AegisAI Synthetic Training Dataset — Risk Label Distribution",
    fontsize=16,
    fontweight="bold",
)

plt.xlabel(
    "Risk Level",
    fontsize=12,
)

plt.ylabel(
    "Number of Samples",
    fontsize=12,
)

plt.grid(
    axis="y",
    linestyle="--",
    alpha=0.3,
)

for bar, count in zip(bars, sample_counts):
    plt.text(
        bar.get_x() + bar.get_width() / 2,
        bar.get_height(),
        str(count),
        ha="center",
        va="bottom",
        fontsize=11,
    )

plt.tight_layout()

output_path = OUTPUT_DIR / "risk_label_distribution.png"

plt.savefig(
    output_path,
    dpi=300,
    bbox_inches="tight",
)

plt.close()

print(f"Graph saved to: {output_path}")
