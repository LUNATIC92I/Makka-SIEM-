#!/usr/bin/env bash
# Lance le backend (port 8765) et le serveur de développement Vite (port 5173) sur 127.0.0.1.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/backend"
[ -d .venv ] || python3 -m venv .venv
.venv/bin/pip install -q -r requirements-dev.txt
.venv/bin/python -m app.run --port 8765 &
BACK=$!
trap 'kill $BACK' EXIT
cd "$ROOT/frontend"
[ -d node_modules ] || npm ci
npm run dev
