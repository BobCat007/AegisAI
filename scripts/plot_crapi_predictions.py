from pathlib import Path

import matplotlib.pyplot as plt


OUTPUT_DIR = Path("reports/graphs")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

risk_levels = [
    "Low",
    "Medium",
    "High",
    "Critical",
]

bfla_probabilities = [
    0.0960,
    0.7031,
    0.0865,
    0.1144,
]

bola_probabilities = [
    0.9964,
    0.0019,
    0.0004,
    0.0013,
]

x = range(len(risk_levels))
width = 0.35

plt.figure(figsize=(11, 6))

bars_bfla = plt.bar(
    [i - width / 2 for i in x],
    bfla_probabilities,
    width,
    label="BFLA target",
)

bars_bola = plt.bar(
    [i + width / 2 for i in x],
    bola_probabilities,
    width,
    label="BOLA target",
)

plt.title(
    "AegisAI Risk Prediction on crAPI Authorization Targets",
    fontsize=16,
    fontweight="bold",
)

plt.xlabel(
    "Predicted Risk Level",
    fontsize=12,
)

plt.ylabel(
    "Prediction Probability",
    fontsize=12,
)

plt.xticks(
    list(x),
    risk_levels,
)

plt.ylim(0, 1.1)

plt.grid(
    axis="y",
    linestyle="--",
    alpha=0.3,
)

plt.legend()

for bar, probability in zip(
    bars_bfla,
    bfla_probabilities,
):
    plt.text(
        bar.get_x() + bar.get_width() / 2,
        bar.get_height(),
        f"{probability:.4f}",
        ha="center",
        va="bottom",
        fontsize=9,
    )

for bar, probability in zip(
    bars_bola,
    bola_probabilities,
):
    plt.text(
        bar.get_x() + bar.get_width() / 2,
        bar.get_height(),
        f"{probability:.4f}",
        ha="center",
        va="bottom",
        fontsize=9,
    )

plt.tight_layout()

output_path = OUTPUT_DIR / "crapi_prediction_probabilities.png"

plt.savefig(
    output_path,
    dpi=300,
    bbox_inches="tight",
)

plt.close()

print(f"Graph saved to: {output_path}")
