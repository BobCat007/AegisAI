#!/usr/bin/env bash

set -Eeuo pipefail

PROJECT_DIR="${HOME}/AegisAI"
cd "$PROJECT_DIR"

echo "=========================================="
echo "       AEGISAI v0.4 HARDENING"
echo "=========================================="

# 1. Verify project
if [[ ! -d ".git" ]]; then
    echo "[ERROR] AegisAI Git repository not found."
    exit 1
fi

if [[ ! -d ".venv" ]]; then
    echo "[ERROR] Python virtual environment not found."
    exit 1
fi

PYTHON=".venv/bin/python"
PYTEST=".venv/bin/pytest"

# 2. Backup environment configuration
if [[ -f ".env" ]]; then
    BACKUP=".env.backup.$(date +%Y%m%d_%H%M%S)"
    cp -p .env "$BACKUP"
    chmod 600 "$BACKUP"
    echo "[OK] Environment backup created."
else
    echo "[WARNING] .env file does not exist."
fi

# 3. Protect environment file
if [[ -f ".env" ]]; then
    chmod 600 .env
    echo "[OK] .env permissions restricted."
fi

# 4. Verify configuration without displaying secrets
echo
echo "========== CONFIGURATION =========="

"$PYTHON" - <<'PY'
import os
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv(".env")
except ImportError:
    pass

for name in (
    "GEMINI_API_KEY",
    "AEGISAI_AUTH_API_KEY",
    "AEGISAI_API_KEY",
):
    value = os.getenv(name, "").strip()
    configured = bool(value) and not value.lower().startswith(
        ("your_", "replace_", "placeholder")
    )
    print(f"{name}: {'CONFIGURED' if configured else 'NOT CONFIGURED'}")

truthy = {"1", "true", "yes", "on"}

for name in ("AEGISAI_AUTH_API_ENABLED", "AEGISAI_API_AUTH_ENABLED"):
    enabled = os.getenv(name, "").strip().lower() in truthy
    print(f"{name}: {'ENABLED' if enabled else 'DISABLED'}")
PY

# 5. Verify Git ignores sensitive files
echo
echo "========== GIT SECRET PROTECTION =========="

if git check-ignore -q .env; then
    echo "[OK] .env is ignored by Git."
else
    echo "[WARNING] .env is not ignored by Git."
    echo "Add .env to .gitignore before committing."
fi

if git ls-files --error-unmatch .env >/dev/null 2>&1; then
    echo "[ERROR] .env is tracked by Git."
    echo "Remove it from tracking and rotate any exposed secrets."
    exit 1
else
    echo "[OK] .env is not tracked by Git."
fi

# 6. Check required security configuration
echo
echo "========== AUTHORIZATION CONFIGURATION =========="

"$PYTHON" - <<'PY'
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(".env")

key = os.getenv("AEGISAI_AUTH_API_KEY", "").strip()

if key and not key.lower().startswith(
    ("your_", "replace_", "placeholder")
):
    print("[OK] Authorization API key is configured.")
else:
    print("[WARNING] Authorization API key is missing.")
    print("Authorization endpoints should remain disabled.")
PY

# 7. Compile Python source
echo
echo "========== PYTHON COMPILATION =========="

"$PYTHON" -m compileall -q ai backend

echo "[OK] Python compilation completed."

# 8. Validate Git whitespace
echo
echo "========== GIT VALIDATION =========="

git diff --check
git diff --cached --check

echo "[OK] Git whitespace validation completed."

# 9. Run test suite
echo
echo "========== AUTOMATED TESTS =========="

"$PYTEST" -q

echo
echo "=========================================="
echo "       HARDENING CHECKS COMPLETED"
echo "=========================================="

echo
echo "Current Git status:"
git status --short

echo
echo "IMPORTANT:"
echo "- Review all warnings."
echo "- Never commit .env or backup files."
echo "- Do not expose API keys in terminal output."
echo "- Keep authorization API disabled until its key is configured."
