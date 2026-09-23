from ai.authorization.findings import AuthorizationFinding


def test_authorization_finding_consistent():
    finding = AuthorizationFinding(
        identity="user-a",
        expected_outcome="allow",
        observed_status_code=200,
        status="consistent",
    )

    assert finding.identity == "user-a"
    assert finding.expected_outcome == "allow"
    assert finding.observed_status_code == 200
    assert finding.status == "consistent"


def test_authorization_finding_inconsistent():
    finding = AuthorizationFinding(
        identity="user-b",
        expected_outcome="deny",
        observed_status_code=200,
        status="inconsistent",
    )

    assert finding.identity == "user-b"
    assert finding.expected_outcome == "deny"
    assert finding.observed_status_code == 200
    assert finding.status == "inconsistent"
