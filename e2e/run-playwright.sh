#!/usr/bin/env bash
# Run the Playwright suite against an already-started local server.
# Expects the server to be running on port 3000.
set -e
cd "$(dirname "$0")/.."
exec npx playwright test