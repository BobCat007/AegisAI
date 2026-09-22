import csv
from pathlib import Path

from api_discovery.models import APIEndpoint, SecurityClassification
from risk_engine.features import extract_feature_vector
from risk_engine.scorer import calculate_risk
from risk_engine.schema import FEATURE_NAMES


OUTPUT_PATH = (
    Path(__file__).resolve().parent.parent
    / "data"
    / "processed"
    / "api_training_data.csv"
)


def build_endpoint(
    path: str,
    method: str,
    operation_category: str,
    *,
    authenticated: bool = False,
    destructive: bool = False,
    path_parameters: bool = False,
    authentication_endpoint: bool = False,
    sensitive_parameters: bool = False,
    parameter_count: int = 0,
    request_body: dict | None = None,
    responses: dict | None = None,
) -> APIEndpoint:
    parameters = []

    if path_parameters:
        parameters.append(
            {
                "name": "id",
                "in": "path",
                "required": True,
                "schema": {
                    "type": "string",
                },
            }
        )

    while len(parameters) < parameter_count:
        parameters.append(
            {
                "name": f"param_{len(parameters) + 1}",
                "in": "query",
                "schema": {
                    "type": "string",
                },
            }
        )

    if sensitive_parameters:
        parameters.append(
            {
                "name": "password",
                "in": "query",
                "schema": {
                    "type": "string",
                },
            }
        )

    classification = SecurityClassification(
        is_authenticated=authenticated,
        is_destructive=destructive,
        has_path_parameters=path_parameters,
        is_authentication_endpoint=authentication_endpoint,
        has_sensitive_parameters=sensitive_parameters,
        sensitive_parameters=(
            ["password"]
            if sensitive_parameters
            else []
        ),
    )

    return APIEndpoint(
        path=path,
        method=method,
        operation_category=operation_category,
        parameters=parameters,
        request_body=request_body,
        responses=responses or {},
        security_classification=classification,
    )


def generate_endpoint_templates() -> list[APIEndpoint]:
    simple_response = {
        "200": {
            "description": "Successful response",
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "id": {
                                "type": "string",
                            }
                        },
                    }
                }
            },
        }
    }

    user_response = {
        "200": {
            "description": "Successful response",
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "id": {
                                "type": "string",
                            },
                            "username": {
                                "type": "string",
                            },
                            "email": {
                                "type": "string",
                            },
                        },
                    }
                }
            },
        }
    }

    nested_response = {
        "200": {
            "description": "Successful response",
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "user": {
                                "type": "object",
                                "properties": {
                                    "profile": {
                                        "type": "object",
                                        "properties": {
                                            "name": {
                                                "type": "string",
                                            }
                                        },
                                    }
                                },
                            }
                        },
                    }
                }
            },
        }
    }

    user_request = {
        "content": {
            "application/json": {
                "schema": {
                    "type": "object",
                    "properties": {
                        "username": {
                            "type": "string",
                        },
                        "email": {
                            "type": "string",
                        },
                    },
                    "required": [
                        "username",
                    ],
                }
            }
        }
    }

    sensitive_request = {
        "content": {
            "application/json": {
                "schema": {
                    "type": "object",
                    "properties": {
                        "username": {
                            "type": "string",
                        },
                        "password": {
                            "type": "string",
                        },
                        "role": {
                            "type": "string",
                        },
                    },
                    "required": [
                        "username",
                        "password",
                    ],
                }
            }
        }
    }

    return [
        build_endpoint(
            "/health",
            "GET",
            "read",
            authenticated=True,
            responses=simple_response,
        ),
        build_endpoint(
            "/users",
            "GET",
            "read",
            authenticated=True,
            parameter_count=1,
            responses=user_response,
        ),
        build_endpoint(
            "/users/{user_id}",
            "GET",
            "read",
            authenticated=True,
            path_parameters=True,
            responses=user_response,
        ),
        build_endpoint(
            "/users",
            "POST",
            "create/action",
            authenticated=True,
            request_body=user_request,
            responses=user_response,
        ),
        build_endpoint(
            "/users/{user_id}",
            "PUT",
            "update",
            authenticated=True,
            path_parameters=True,
            request_body=user_request,
            responses=user_response,
        ),
        build_endpoint(
            "/users/{user_id}",
            "PATCH",
            "update",
            authenticated=True,
            path_parameters=True,
            request_body=user_request,
            responses=user_response,
        ),
        build_endpoint(
            "/users/{user_id}",
            "DELETE",
            "delete",
            authenticated=True,
            path_parameters=True,
            responses=simple_response,
        ),
        build_endpoint(
            "/auth/login",
            "POST",
            "create/action",
            authentication_endpoint=True,
            sensitive_parameters=True,
            request_body=sensitive_request,
            responses=user_response,
        ),
        build_endpoint(
            "/admin/users/{user_id}",
            "DELETE",
            "delete",
            authenticated=True,
            destructive=True,
            path_parameters=True,
            sensitive_parameters=True,
            parameter_count=2,
            responses=nested_response,
        ),
        build_endpoint(
            "/admin/users/{user_id}/credentials",
            "PUT",
            "update",
            authenticated=True,
            destructive=True,
            path_parameters=True,
            sensitive_parameters=True,
            parameter_count=3,
            request_body=sensitive_request,
            responses=nested_response,
        ),
        build_endpoint(
            "/public/search",
            "GET",
            "read",
            parameter_count=3,
            responses=user_response,
        ),
        build_endpoint(
            "/internal/config",
            "GET",
            "read",
            authenticated=True,
            parameter_count=5,
            responses=nested_response,
        ),
    ]


def get_risk_label(endpoint: APIEndpoint) -> str:
    """
    Convert the deterministic baseline risk assessment into
    a training label.
    """

    assessment = calculate_risk(endpoint)

    return assessment.severity


def write_dataset(endpoints: list[APIEndpoint]) -> None:
    OUTPUT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with OUTPUT_PATH.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as file:
        writer = csv.writer(file)

        writer.writerow(
            [
                *FEATURE_NAMES,
                "risk_label",
            ]
        )

        for endpoint in endpoints:
            feature_vector = extract_feature_vector(endpoint)
            risk_label = get_risk_label(endpoint)

            writer.writerow(
                [
                    *feature_vector,
                    risk_label,
                ]
            )


def main() -> None:
    endpoints = generate_endpoint_templates()

    write_dataset(endpoints)

    print(
        f"Generated {len(endpoints)} API endpoint samples."
    )
    print(
        f"Dataset written to: {OUTPUT_PATH}"
    )


if __name__ == "__main__":
    main()
