#!/bin/bash
set -euo pipefail

# Get DATABASE_URL from cluster secret
DATABASE_URL=$(kubectl get secret identity-service-db-conn -n platform-identity -o jsonpath='{.data.DATABASE_URL}' | base64 -d)

echo "Running integration test in cluster..."
echo "Database URL configured"

kubectl run integration-test-oidc --image=identity-service:ci-test --rm -i --restart=Never -n platform-identity --overrides="{
  \"spec\": {
    \"containers\": [{
      \"name\": \"integration-test-oidc\",
      \"image\": \"identity-service:ci-test\",
      \"command\": [\"npm\", \"run\", \"test:integration\", \"--\", \"tests/integration/test_oidc_login_flow.ts\"],
      \"env\": [
        {\"name\": \"DATABASE_URL\", \"value\": \"$DATABASE_URL\"},
        {\"name\": \"NODE_ENV\", \"value\": \"test\"}
      ]
    }]
  }
}"