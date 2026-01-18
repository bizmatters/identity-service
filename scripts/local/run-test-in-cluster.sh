#!/bin/bash
set -euo pipefail

# Get DB credentials from cluster
POSTGRES_HOST=$(kubectl get secret identity-service-db-conn -n platform-identity -o jsonpath='{.data.POSTGRES_HOST}' | base64 -d)
POSTGRES_PORT=$(kubectl get secret identity-service-db-conn -n platform-identity -o jsonpath='{.data.POSTGRES_PORT}' | base64 -d)
POSTGRES_USER=$(kubectl get secret identity-service-db-conn -n platform-identity -o jsonpath='{.data.POSTGRES_USER}' | base64 -d)
POSTGRES_PASSWORD=$(kubectl get secret identity-service-db-conn -n platform-identity -o jsonpath='{.data.POSTGRES_PASSWORD}' | base64 -d)
POSTGRES_DB=$(kubectl get secret identity-service-db-conn -n platform-identity -o jsonpath='{.data.POSTGRES_DB}' | base64 -d)

echo "Running integration test in cluster..."
echo "Database: $POSTGRES_HOST:$POSTGRES_PORT/$POSTGRES_DB"

kubectl run integration-test-oidc --image=identity-service:ci-test --rm -i --restart=Never -n platform-identity --overrides="{
  \"spec\": {
    \"containers\": [{
      \"name\": \"integration-test-oidc\",
      \"image\": \"identity-service:ci-test\",
      \"command\": [\"npm\", \"run\", \"test:integration\", \"--\", \"tests/integration/test_oidc_login_flow.ts\"],
      \"env\": [
        {\"name\": \"POSTGRES_HOST\", \"value\": \"$POSTGRES_HOST\"},
        {\"name\": \"POSTGRES_PORT\", \"value\": \"$POSTGRES_PORT\"},
        {\"name\": \"POSTGRES_USER\", \"value\": \"$POSTGRES_USER\"},
        {\"name\": \"POSTGRES_PASSWORD\", \"value\": \"$POSTGRES_PASSWORD\"},
        {\"name\": \"POSTGRES_DB\", \"value\": \"$POSTGRES_DB\"},
        {\"name\": \"NODE_ENV\", \"value\": \"test\"}
      ]
    }]
  }
}"