#!/usr/bin/env bash
# Clone the repo into a temporary folder, install it and run the tests.
# Catches files that exist on your laptop but were never committed.
# Usage: bash scripts/verify_fresh_clone.sh [repo-url]
set -euo pipefail

REPO="${1:-https://github.com/gaurav-11-cyber/Cyber-Hackathon.git}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "Cloning $REPO ..."
git clone --quiet "$REPO" "$WORK/repo"
cd "$WORK/repo"

python3 -m venv .venv
source .venv/bin/activate
pip install --quiet -r requirements.txt -r requirements-dev.txt

echo "Running tests ..."
python -m pytest -q

echo "Checking that the app imports ..."
python - << 'PY'
import analyze, analyzer.ai, analyzer.report, analyzer.intel, analyzer.correlate  # noqa: F401
print("imports ok")
PY
echo "FRESH CLONE OK"
