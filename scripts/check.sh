#!/usr/bin/env bash
# Local equivalent of .github/workflows/ci.yml (Linux/macOS). Exits non-zero on the first
# failing step. Usage: scripts/check.sh [--skip-e2e]
# NOTE: written for Linux CI parity but NOT yet run on Linux (only Windows was available).
set -euo pipefail
cd "$(dirname "$0")/.."

echo "Environment: $(uname -srm); $(uv run python --version); node $(node --version)"
step() { echo "==> $1"; shift; "$@"; }

step "uv sync --locked" uv sync --locked
step "ruff check" uv run ruff check .
step "ruff format --check" uv run ruff format --check .
step "mypy" uv run mypy src
step "pytest" uv run pytest -q
step "uv build" uv build --out-dir dist
step "inspect dist" uv run python scripts/inspect_dist.py dist
cd apps/web
step "npm ci" npm ci
step "typecheck" npm run typecheck
step "vitest" npm test
step "build" npm run build
if [[ "${1:-}" != "--skip-e2e" ]]; then
  step "playwright e2e" npx playwright test
fi
echo "All steps passed."
