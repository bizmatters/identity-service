## REDIS Cache
REDIS is running inside the cluster. for your testing outside cluster use - 
use this Public endpoint in .env for local testing - redis-10486.crce276.ap-south-1-3.ec2.cloud.redislabs.com:10486
it can use localhost when testing in k8 cluster as redis is already running in cluster.

## Cluster commands for debugging
kubectl get pods -n platform-identity
kubectl get pods -n platform-identity
kubectl logs -n platform-identity deployment/identity-service --tail=20
kubectl delete pod -n platform-identity -l app=identity-service
kubectl get deployment identity-service -n platform-identity -o yaml | grep -A 10 -B 5 envFrom
kubectl get secrets -n platform-identity | grep identity-service

## JWKS AUTH RESPONSE
curl -s "https://ep-late-cherry-afaerbwj.neonauth.c-2.us-west-2.aws.neon.tech/neondb/auth/.well-known/jwks.json" | head -5
{"keys":[{"alg":"EdDSA","crv":"Ed25519","x":"DWRL8ChRGxV1Yq_PCtL3
h6pwj1qCppiOv1cOhPBlqG8","kty":"OKP","kid":"fdaebf28-d281-4d9d-9ba4-0be06049d783"}]}%   

## INTEGRATION TESTING
docker build -t identity-service:ci-test .
kind load docker-image identity-service:ci-test --name zerotouch-preview

kubectl run integration-test-oidc --image=identity-service:ci-test --rm -i --restart=Never -n platform-identity --overrides='
{
  "spec": {
    "containers": [
      {
        "name": "integration-test-oidc",
        "image": "identity-service:ci-test",
        "command": ["npm", "run", "test:integration", "--", "tests/integration/test_neon_auth_login_flow.ts"],
        "env": [
          {"name": "DATABASE_URL", "value": "postgresql://neondb_owner:npg_lhaL8SJCzD9v@ep-flat-feather-aekziod9-pooler.c-2.us-east-2.aws.neon.tech/neondb?sslmode=require"},
          {"name": "NEON_AUTH_URL", "value": "https://ep-flat-feather-aekziod9.neonauth.c-2.us-east-2.aws.neon.tech/neondb/auth"},
          {"name": "NEON_JWKS_URL", "value": "https://ep-flat-feather-aekziod9.neonauth.c-2.us-east-2.aws.neon.tech/neondb/auth/.well-known/jwks.json"},
          {"name": "REDIS_HOST", "value": "localhost"},
          {"name": "REDIS_PORT", "value": "6379"},
          {"name": "NODE_ENV", "value": "test"}
        ]
      }
    ]
  }
}'

kubectl run test-oidc --image=curlimages/curl --rm -i --restart=Never -n platform-identity -- curl -s "http://identity-service.platform-identity.svc.cluster.local:3000/auth/login/google"

## Testing in-cluster service
kubectl port-forward -n platform-identity svc/identity-service 3000:3000 &

curl -s http://localhost:3000/auth/login
curl -s "http://localhost:3000/auth/login?redirect_uri=https://localhost:3000"
 