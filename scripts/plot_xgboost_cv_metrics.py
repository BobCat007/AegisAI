from pathlib import Path

import matplotlib.pyplot as plt


OUTPUT_DIR = Path("reports/graphs")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

metrics = [
    "Accuracy",
    "Macro Precision",
    "Macro Recall",
    "Macro F1",
]

scores = [
    1.00,
    1.00,
    1.00,
    1.00,
]

plt.figure(figsize=(10, 6))

bars = plt.bar(
    metrics,
    scores,
)

plt.title(
    "AegisAI XGBoost Risk Prediction — 3-Fold Cross-Validation",
    fontsize=16,
    fontweight="bold",
)

plt.xlabel(
    "Evaluation Metric",
    fontsize=12,
)

plt.ylabel(
    "Score",
    fontsize=12,
)

plt.ylim(0, 1.1)

plt.grid(
    axis="y",
    linestyle="--",
    alpha=0.3,
)

for bar, score in zip(bars, scores):
    plt.text(
        bar.get_x() + bar.get_width() / 2,
        bar.get_height(),
        f"{score:.2f}",
        ha="center",
        va="bottom",
        fontsize=11,
    )

plt.tight_layout()

output_path = OUTPUT_DIR / "xgboost_cv_metrics.png"

plt.savefig(
    output_path,
    dpi=300,
    bbox_inches="tight",
)

plt.close()

print(f"Graph saved to: {output_path}")
