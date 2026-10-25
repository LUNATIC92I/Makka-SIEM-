#!/usr/bin/env bash
# Contrôles locaux avant distribution : tests, audit des dépendances, analyse statique.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PYTHON:-$ROOT/backend/.venv/bin/python}"
status=0
echo "== pytest";        (cd "$ROOT/backend" && "$PY" -m pytest -q) || status=1
echo "== bandit";        (cd "$ROOT/backend" && "$PY" -m bandit -q -r app -ll) || status=1
echo "== pip-audit";     (cd "$ROOT/backend" && "$PY" -m pip_audit -r requirements.txt) || status=1
echo "== frontend";      (cd "$ROOT/frontend" && npm test && npm run build >/dev/null) || status=1
echo "== npm audit";     (cd "$ROOT/frontend" && npm audit --omit=dev) || status=1
exit $status
