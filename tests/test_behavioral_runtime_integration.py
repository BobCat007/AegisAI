import random

from ai.behavioral_intelligence.detector import (
    IsolationForestBehavioralDetector,
)
from ai.behavioral_intelligence.synthetic import (
    generate_normal_observations,
)
from ai.telemetry.models import TelemetryEvent
from ai.telemetry.processor import aggregate_events
from tools.telemetry_sender import generate_events


def test_runtime_behavioral_detection_across_traffic_scenarios():
    # Train independently so this test does not depend on a saved model.
    detector = IsolationForestBehavioralDetector()
    baseline = generate_normal_observations(
        count=1500,
        random_state=42,
    )
    detector.fit(baseline)

    # Make telemetry generation deterministic without affecting
    # the random state used by other tests.
    previous_random_state = random.getstate()

    try:
        random.seed(42)
        rates = {}

        for scenario in ("normal", "suspicious", "mixed"):
            total = 0
            anomalous = 0

            for _ in range(10):
                raw_events = generate_events(
                    count=100,
                    scenario=scenario,
                )

                events = [
                    TelemetryEvent.model_validate(item)
                    for item in raw_events
                ]

                observations = aggregate_events(events)
                results = detector.predict(observations)

                total += len(results)
                anomalous += sum(
                    result.classification == "anomalous"
                    for result in results
                )

            assert total > 0, f"{scenario}: no observations generated"
            rates[scenario] = anomalous / total

        assert rates["normal"] <= 0.10, (
            f"Normal traffic false-positive rate too high: "
            f"{rates['normal']:.1%}"
        )

        assert rates["suspicious"] >= 0.90, (
            f"Suspicious traffic detection rate too low: "
            f"{rates['suspicious']:.1%}"
        )

        assert 0.10 <= rates["mixed"] <= 0.50, (
            f"Mixed traffic anomaly rate outside expected range: "
            f"{rates['mixed']:.1%}"
        )

    finally:
        random.setstate(previous_random_state)
