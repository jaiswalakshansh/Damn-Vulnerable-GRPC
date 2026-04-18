#!/usr/bin/env bash
set -euo pipefail

echo "[devcontainer] Installing DVGRPC dev environment…"

pip install --upgrade pip
pip install -r requirements.txt -r requirements-dev.txt

# grpcurl is the workhorse CLI for these challenges
if ! command -v grpcurl >/dev/null 2>&1; then
    echo "[devcontainer] Installing grpcurl…"
    go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest || true
fi

# Pre-compile proto stubs so imports work out of the box
make proto || true

echo ""
echo "  Ready. Try:"
echo "    make run           # start the server"
echo "    make scoreboard    # track your progress"
echo "    make exploit N=01  # run the first challenge exploit"
