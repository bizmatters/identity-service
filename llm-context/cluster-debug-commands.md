kubectl get pods -n platform-identity
kubectl get pods -n platform-identity
kubectl logs -n platform-identity deployment/identity-service --tail=20

# TESTING
docker build -t identity-service:ci-test .
kind load docker-image identity-service:ci-test --name zerotouch-preview

kubectl run integration-test-oidc --image=identity-service:ci-test --rm -i --restart=Never -n platform-identity --overrides='
{
  "spec": {
    "containers": [
      {
        "name": "integration-test-oidc",
        "image": "identity-service:ci-test",
        "command": ["npm", "run", "test:integration", "--", "tests/integration/test_oidc_login_flow.ts"],
        "env": [
          {"name": "POSTGRES_HOST", "value": "identity-service-db-rw.platform-identity.svc.cluster.local"},
          {"name": "POSTGRES_PORT", "value": "5432"},
          {"name": "POSTGRES_USER", "value": "identity-service-db"},
          {"name": "POSTGRES_PASSWORD", "value": "test-password"},
          {"name": "POSTGRES_DB", "value": "identity-service-db"},
          {"name": "REDIS_HOST", "value": "identity-cache.platform-identity.svc.cluster.local"},
          {"name": "REDIS_PORT", "value": "6379"},
          {"name": "OIDC_ISSUER", "value": "https://ep-late-cherry-afaerbwj.neonauth.us-west-2.aws.neon.tech/neondb/auth"},
          {"name": "OIDC_CLIENT_ID", "value": "identity-service-dev"},
          {"name": "OIDC_CLIENT_SECRET", "value": "neon-managed-secret"},
          {"name": "JWT_PRIVATE_KEY", "value": "test-private-key"},
          {"name": "JWT_PUBLIC_KEY", "value": "test-public-key"},
          {"name": "JWT_KEY_ID", "value": "test-key-id"}
        ]
      }
    ]
  }
}'

kubectl port-forward -n platform-identity svc/identity-service 3000:3000 &

curl -s http://localhost:3000/auth/login
curl -s "http://localhost:3000/auth/login?redirect_uri=https://localhost:3000"
