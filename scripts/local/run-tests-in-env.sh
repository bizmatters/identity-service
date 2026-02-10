#!/bin/bash
set -euo pipefail

# ==============================================================================
# Service Entry Point for Running Tests in Environment
# ==============================================================================
# Purpose: Run integration tests in existing cluster (dev/staging/prod)
# Usage: ./scripts/local/run-tests-in-env.sh <environment>
# Example: ./scripts/local/run-tests-in-env.sh dev
# ==============================================================================

ENVIRONMENT="${1:-dev}"

# Get service name from config
if [[ -f "ci/config.yaml" ]]; then
    if command -v yq &> /dev/null; then
        SERVICE_NAME=$(yq eval '.service.name' ci/config.yaml)
    else
        echo "Error: yq is required but not installed"
        exit 1
    fi
else
    echo "Error: ci/config.yaml not found"
    exit 1
fi

# Get platform branch from service config
if command -v yq &> /dev/null; then
    PLATFORM_BRANCH=$(yq eval '.platform.branch // "main"' ci/config.yaml)
else
    PLATFORM_BRANCH="main"
fi

# Always ensure fresh platform checkout
if [[ -d "zerotouch-platform" ]]; then
    echo "Removing existing platform checkout for fresh clone..."
    rm -rf zerotouch-platform
fi

echo "Cloning fresh zerotouch-platform repository (branch: $PLATFORM_BRANCH)..."
git clone -b "$PLATFORM_BRANCH" https://github.com/arun4infra/zerotouch-platform.git zerotouch-platform

# Run platform script
PLATFORM_SCRIPT="./zerotouch-platform/scripts/bootstrap/helpers/run-tests-in-env.sh"

if [[ ! -f "$PLATFORM_SCRIPT" ]]; then
    echo "Error: Platform script not found: $PLATFORM_SCRIPT"
    exit 1
fi

chmod +x "$PLATFORM_SCRIPT"
"$PLATFORM_SCRIPT" "$SERVICE_NAME" "$ENVIRONMENT"
