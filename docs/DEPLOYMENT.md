# AegisAI Deployment Guide

## Requirements
- Docker Desktop with WSL2 integration, or compatible Docker Engine
- Docker Compose
- AegisAI project checkout

## Environment
Configure `.env` using `.env.example` as a reference.

Required security configuration:
- AEGISAI_API_AUTH_ENABLED
- AEGISAI_API_KEY
- AEGISAI_RATE_LIMIT_ENABLED
- AEGISAI_RATE_LIMIT_REQUESTS
- AEGISAI_RATE_LIMIT_WINDOW_SECONDS

For Gemini Copilot:
- GEMINI_API_KEY
- AEGISAI_GEMINI_MODEL
- AEGISAI_GEMINI_TIMEOUT_SECONDS

Never commit or share `.env`.

## Build and start

```bash
docker compose config -q
docker compose build
docker compose up -d
docker compose ps
```

Dashboard: http://localhost:8080

## Health checks

Run `curl -i http://localhost:8080/health` and `docker compose ps`.
Inspect logs with `docker compose logs --tail=80 backend`.

## Restart and stop

- Restart: `docker compose restart`
- Stop: `docker compose stop`
- Start: `docker compose up -d`

Avoid `docker compose down -v` unless intentional data deletion is required.

## Persistent data

The local `data/` directory is mounted into the backend container. It stores models, telemetry, incidents, alerts, response audit records, and knowledge documents. Back it up before upgrades or maintenance.

## Security considerations

- The backend port is not directly published to the host.
- The frontend is bound to localhost by default.
- Nginx proxies API requests and injects the configured API key.
- Direct backend API requests without a valid key should be rejected.
- The proxy trusts local dashboard access; it does not provide individual user authentication.
- Do not expose this deployment publicly without additional authentication, TLS, secret management, and security validation.
- Rate limiting is in-memory and process-local.
- Automated response execution remains dry-run only.
- Behavioral model validation includes synthetic data and does not establish production effectiveness.

## Troubleshooting

Inspect services with `docker compose ps -a`.
Inspect logs with `docker compose logs --tail=100`.
Validate configuration with `docker compose config -q`.

If Docker is unavailable in WSL2, check Docker Desktop and Ubuntu WSL integration.
