from ai.graph_intelligence.builder import build_security_graph
from scripts.generate_graph_scenarios import build_graph_scenarios
from scripts.generate_training_data import generate_endpoint_templates
from scripts.graph_training_data import build_graph_training_samples


def test_graph_scenarios_can_pair_with_training_endpoints():
    endpoints = generate_endpoint_templates()
    scenarios = build_graph_scenarios()

    assert len(endpoints) > 0
    assert len(scenarios) == 6

    total_samples = len(endpoints) * len(scenarios)

    assert total_samples == len(endpoints) * 6


def test_graph_training_sample_vectors_have_28_features():
    endpoints = generate_endpoint_templates()
    scenarios = build_graph_scenarios()

    sample_count = 0

    for endpoint in endpoints:
        for scenario in scenarios:
            graph = build_security_graph(scenario)

            from ai.security_context_features import (
                build_security_context_feature_vector,
            )

            vector = build_security_context_feature_vector(
                endpoint,
                graph,
            )

            assert len(vector) == 28

            sample_count += 1

    assert sample_count == len(endpoints) * len(scenarios)


def test_graph_training_samples_have_features_and_labels():
    endpoints = generate_endpoint_templates()

    samples = build_graph_training_samples(endpoints)

    assert len(samples) == len(endpoints) * 6

    for feature_vector, risk_label in samples:
        assert len(feature_vector) == 28
        assert risk_label in {
            "low",
            "medium",
            "high",
            "critical",
        }


def test_graph_training_samples_preserve_endpoint_labels():
    endpoints = generate_endpoint_templates()

    samples = build_graph_training_samples(endpoints)

    endpoint_labels = [
        endpoint
        for endpoint in endpoints
    ]

    expected_labels = []

    for endpoint in endpoint_labels:
        expected_labels.extend(
            [endpoint for _ in range(6)]
        )

    actual_labels = [
        risk_label
        for _, risk_label in samples
    ]

    from scripts.generate_training_data import get_risk_label

    expected_labels = [
        get_risk_label(endpoint)
        for endpoint in endpoints
        for _ in range(6)
    ]

    assert actual_labels == expected_labels
