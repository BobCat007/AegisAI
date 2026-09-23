from api_discovery.models import APIObjectOperationSurface
from ai.graph_intelligence.builder import build_security_graph
from ai.security_context_features import build_security_context_feature_vector
from scripts.generate_graph_scenarios import build_graph_scenarios
from scripts.generate_training_data import build_endpoint


def test_training_endpoint_with_graph_context():
    endpoint = build_endpoint(
        path="/users/{user_id}",
        method="DELETE",
        operation_category="delete",
        authenticated=True,
        destructive=True,
        path_parameters=True,
        parameter_count=2,
    )

    scenario = build_graph_scenarios()[5]
    graph = build_security_graph(scenario)

    vector = build_security_context_feature_vector(
        endpoint,
        graph,
    )

    assert len(vector) == 31

    assert vector[:25] == [
        float(value)
        for value in vector[:25]
    ]

    assert vector[25:] == [
        1.0,
        0.0,
        0.0,
        0.0,
        1.0,
        0.0,
    ]
