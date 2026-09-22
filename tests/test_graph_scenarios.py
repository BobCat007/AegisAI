from scripts.generate_graph_scenarios import build_graph_scenarios


def test_graph_scenarios_are_generated():
    scenarios = build_graph_scenarios()

    assert len(scenarios) == 6
    assert all(scenarios)


def test_graph_scenarios_have_valid_surfaces():
    scenarios = build_graph_scenarios()

    for scenario in scenarios:
        for surface in scenario:
            assert surface.path_template
            assert surface.object_identifier_names
            assert surface.operations


def test_graph_scenarios_have_different_operation_structures():
    scenarios = build_graph_scenarios()

    operation_sets = {
        tuple(surface.operations)
        for scenario in scenarios
        for surface in scenario
    }

    assert len(operation_sets) >= 5
