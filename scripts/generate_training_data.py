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
    header_parameter_count: int = 0,
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

    for index in range(header_parameter_count):
        parameters.append(
            {
                "name": f"X-Custom-Header-{index + 1}",
                "in": "header",
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


def generate_response(
    property_count: int = 1,
    depth: int = 1,
) -> dict:
    properties = {}

    for index in range(property_count):
        properties[f"field_{index + 1}"] = {
            "type": "string",
        }

    current_schema = {
        "type": "object",
        "properties": properties,
    }

    for level in range(depth - 1):
        current_schema = {
            "type": "object",
            "properties": {
                f"nested_{level + 1}": current_schema,
            },
        }

    return {
        "200": {
            "description": "Successful response",
            "content": {
                "application/json": {
                    "schema": current_schema,
                }
            },
        }
    }


def generate_empty_response(
    status_code: str = "204",
) -> dict:
    return {
        status_code: {
            "description": "Successful response with no body",
        }
    }


def generate_request_body(
    property_count: int = 1,
    required_count: int = 0,
    depth: int = 1,
    sensitive: bool = False,
) -> dict:
    properties = {}

    for index in range(property_count):
        properties[f"field_{index + 1}"] = {
            "type": "string",
        }

    if sensitive and property_count > 0:
        properties["password"] = {
            "type": "string",
        }

    required = []

    for index in range(
        min(required_count, property_count)
    ):
        required.append(f"field_{index + 1}")

    if sensitive:
        required.append("password")

    current_schema = {
        "type": "object",
        "properties": properties,
    }

    if required:
        current_schema["required"] = required

    for level in range(depth - 1):
        current_schema = {
            "type": "object",
            "properties": {
                f"nested_{level + 1}": current_schema,
            },
        }

    return {
        "content": {
            "application/json": {
                "schema": current_schema,
            }
        }
    }


def generate_endpoint_templates() -> list[APIEndpoint]:
    endpoints = []

    response_profiles = [
        generate_response(
            property_count=1,
            depth=1,
        ),
        generate_response(
            property_count=3,
            depth=1,
        ),
        generate_response(
            property_count=5,
            depth=2,
        ),
        generate_response(
            property_count=8,
            depth=3,
        ),
        generate_empty_response(
            status_code="204",
        ),
    ]

    request_profiles = [
        None,
        generate_request_body(
            property_count=2,
            required_count=1,
            depth=1,
        ),
        generate_request_body(
            property_count=4,
            required_count=2,
            depth=2,
        ),
        generate_request_body(
            property_count=6,
            required_count=4,
            depth=3,
        ),
        generate_request_body(
            property_count=4,
            required_count=2,
            depth=2,
            sensitive=True,
        ),
    ]

    resources = [
        "users",
        "accounts",
        "orders",
        "profiles",
        "documents",
        "payments",
        "devices",
        "sessions",
        "projects",
        "files",
    ]

    methods = [
        ("GET", "read"),
        ("POST", "create/action"),
        ("PUT", "update"),
        ("PATCH", "update"),
        ("DELETE", "delete"),
    ]

    for resource_index, resource in enumerate(resources):
        response = response_profiles[
            resource_index % len(response_profiles)
        ]

        for method_index, (method, category) in enumerate(methods):
            use_path_parameter = (
                method in {"PUT", "PATCH", "DELETE"}
                or resource_index % 3 == 0
            )

            authenticated = (
                resource_index % 4 != 0
            )

            destructive = method in {
                "DELETE",
            }

            sensitive = (
                resource_index % 5 == 0
                and method in {"POST", "PUT", "PATCH"}
            )

            request_body = None

            if method in {"POST", "PUT", "PATCH"}:
                request_body = request_profiles[
                    (
                        resource_index
                        + method_index
                    )
                    % len(request_profiles)
                ]

            parameter_count = (
                resource_index % 4
            )

            header_parameter_count = (
                (resource_index + method_index) % 3
            )

            endpoints.append(
                build_endpoint(
                    path=(
                        f"/{resource}"
                        f"/{{{resource[:-1]}_id}}"
                        if use_path_parameter
                        else f"/{resource}"
                    ),
                    method=method,
                    operation_category=category,
                    authenticated=authenticated,
                    destructive=destructive,
                    path_parameters=use_path_parameter,
                    sensitive_parameters=sensitive,
                    parameter_count=parameter_count,
                    header_parameter_count=header_parameter_count,
                    request_body=request_body,
                    responses=response,
                )
            )

    special_endpoints = [
        build_endpoint(
            "/health",
            "GET",
            "read",
            authenticated=True,
            responses=generate_response(
                property_count=1,
                depth=1,
            ),
        ),
        build_endpoint(
            "/health/check",
            "GET",
            "read",
            authenticated=False,
            responses=generate_empty_response(
                status_code="204",
            ),
        ),
        build_endpoint(
            "/auth/login",
            "POST",
            "create/action",
            authentication_endpoint=True,
            sensitive_parameters=True,
            header_parameter_count=1,
            request_body=generate_request_body(
                property_count=3,
                required_count=2,
                depth=1,
                sensitive=True,
            ),
            responses=generate_response(
                property_count=3,
                depth=1,
            ),
        ),
        build_endpoint(
            "/auth/reset-password",
            "POST",
            "create/action",
            authentication_endpoint=True,
            sensitive_parameters=True,
            header_parameter_count=2,
            request_body=generate_request_body(
                property_count=4,
                required_count=3,
                depth=2,
                sensitive=True,
            ),
            responses=generate_response(
                property_count=2,
                depth=1,
            ),
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
            header_parameter_count=2,
            responses=generate_empty_response(
                status_code="204",
            ),
        ),
        build_endpoint(
            "/admin/accounts/{account_id}/credentials",
            "PUT",
            "update",
            authenticated=True,
            destructive=True,
            path_parameters=True,
            sensitive_parameters=True,
            parameter_count=3,
            header_parameter_count=3,
            request_body=generate_request_body(
                property_count=5,
                required_count=4,
                depth=3,
                sensitive=True,
            ),
            responses=generate_response(
                property_count=8,
                depth=3,
            ),
        ),
        build_endpoint(
            path="/admin/users/{user_id}/credentials",
            method="DELETE",
            operation_category="delete",
            authenticated=True,
            destructive=True,
            path_parameters=True,
            authentication_endpoint=True,
            sensitive_parameters=True,
            parameter_count=3,
        ),
        build_endpoint(
            path="/admin/accounts/{account_id}/secrets",
            method="PUT",
            operation_category="update",
            authenticated=True,
            destructive=True,
            path_parameters=True,
            authentication_endpoint=True,
            sensitive_parameters=True,
            parameter_count=3,
        ),
        build_endpoint(
            path="/admin/payments/{payment_id}/credentials",
            method="PATCH",
            operation_category="update",
            authenticated=True,
            destructive=True,
            path_parameters=True,
            authentication_endpoint=True,
            sensitive_parameters=True,
            parameter_count=3,
        ),
        build_endpoint(
            "/internal/configuration",
            "GET",
            "read",
            authenticated=True,
            parameter_count=5,
            header_parameter_count=2,
            responses=generate_response(
                property_count=8,
                depth=3,
            ),
        ),
        build_endpoint(
            "/public/search",
            "GET",
            "read",
            parameter_count=3,
            header_parameter_count=1,
            responses=generate_response(
                property_count=5,
                depth=2,
            ),
        ),
    ]

    endpoints.extend(special_endpoints)

    return endpoints


def get_risk_label(endpoint: APIEndpoint) -> str:
    """
    Convert the deterministic baseline risk assessment
    into a training label.
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
            feature_vector = extract_feature_vector(
                endpoint
            )

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
