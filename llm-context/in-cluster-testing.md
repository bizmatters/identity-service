## Cluster commands for debugging
kubectl get pods -n platform-identity
kubectl get pods -n platform-identity
kubectl logs -n platform-identity deployment/identity-service --tail=20
kubectl delete pod -n platform-identity -l app=identity-service
kubectl get deployment identity-service -n platform-identity -o yaml | grep -A 10 -B 5 envFrom
kubectl get secrets -n platform-identity | grep identity-service

## Check cluster memory usage
docker stats zerotouch-preview-control-plane --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}"
docker stats zerotouch-preview-control-plane --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}"

## AWS SSM Parameter Store
aws ssm put-parameter --name "/zerotouch/prod/identity-service/node_env" --value "pr" --type "String" --overwrite
aws ssm get-parameter --name "/zerotouch/prod/identity-service/neon_auth_url" --with-decryption

## JWKS AUTH RESPONSE
curl -s "https://ep-late-cherry-afaerbwj.neonauth.c-2.us-west-2.aws.neon.tech/neondb/auth/.well-known/jwks.json" | head -5
{"keys":[{"alg":"EdDSA","crv":"Ed25519","x":"DWRL8ChRGxV1Yq_PCtL3
h6pwj1qCppiOv1cOhPBlqG8","kty":"OKP","kid":"fdaebf28-d281-4d9d-9ba4-0be06049d783"}]}%   

## INTEGRATION TESTING
docker build -t identity-service:ci-test .
kind load docker-image identity-service:ci-test --name zerotouch-preview

### Use this command when all env.var in-cluster ES already exists

kubectl run integration-test-oidc --image=identity-service:ci-test --rm -i --restart=Never -n platform-identity --overrides='
{
  "spec": {
    "containers": [
      {
        "name": "integration-test-oidc",
        "image": "identity-service:ci-test",
        "command": ["npm", "run", "test:integration", "--", "tests/integration/test_neon_auth_login_flow.ts"],
        "envFrom": [
          {"configMapRef": {"name": "identity-service-backend-config", "optional": true}},
          {"secretRef": {"name": "identity-service-oidc", "optional": true}},
          {"secretRef": {"name": "identity-service-db", "optional": true}},
          {"secretRef": {"name": "identity-cache-conn", "optional": true}},
          {"secretRef": {"name": "identity-service-jwt", "optional": true}}
        ]
      }
    ]
  }
}'

### Use this command when all env.var in-cluster ES do not exist and you want to pass them as .env file or sources and valiate before creating the ES

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
          {"name": "REDIS_HOST", "value": "identity-cache-0.platform-identity.svc.cluster.local"},
          {"name": "REDIS_PORT", "value": "6379"},
          {"name": "NODE_ENV", "value": "pr"},
          {"name": "JWT_PRIVATE_KEY", "value": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA4AryMGWoRkvqHpcOsZxPOg75Bpwmu0epn2ENJrnXgkfsv2C5\nbDXmm0K7CvbqVNDx9WOS13S5iEemoFqhXMNfIYPeOYt4wu8h5AUpM1L+cPjzo3hy\nSjIY4z962ppzojP3G0SejCeKq5k9SgfuQRVorlWcxYdykK6fN8uwpYjsi7mXfbSB\nXjBfI/GL3Wyk5vGgHy/y2rk/uAAEdv2Ip4bpOTSI7V+t+hOE+yNCUdUJuySwnTM1\nVnWZSllRhb9LRz5Mo9gvxF5MpO1J+Q51wSjar4K1/eaGqANNNmQm8PzeIpEWmlX3\ntgbm6jf2RJUvJd4FGv3vAbHsndQUj+4TA8j2dwIDAQABAoIBAQDLIMGCpbiSu6Nx\nxq141Op0Dj00BAGNzSR6L0j4Moi1QzbgMPcMqDYD0NW61DGTYrntLTFmjRrl92iY\nfHNOoogu39tsuwprWtqUXSWEthuhG+Xx8XNV1+P+rYBakKyEhK7nFyjUk8lDWbVa\n2KPoeFunrFFuOibiDKCoutHW07T73D+xqRH5m1q7Xwum3CkKnpXDy1Xsoo02ySMD\nikqLUCS6CZLKHCqIijv/7l+kv7Z/f525Ag4oQhWjsnyFz9r4YSjKAjmzRRypMKhN\n1CFUg0qWGr8XEND8YB66sss1GU+OPG6+0tWBODALUZpcalhmrwi/bKr+Ef/SmQ8o\n3DTNEWXRAoGBAPKolCu0pv8r9EftooZi0yPxZkAJ9PwFOTwUkY5xVedyblCcg+vL\nV97K2ohASI/+Q+N8afEKO9l8SdjH0anCU3rUTlW0Ofx5i5yEaluAWyYgSROMVsbx\nWKbUeRQ5pb5KV079ohDSePET0Dvp7cwKfCMQ4e8LE1ofhFsWTsfanq4/AoGBAOxc\nWa9j3UH4eQp4ydS6MOFWj+B51HpBBUoopAVAYLfEJ0wbCuXq5gHEVxWOfYqm0HwG\nOdgd/Kghm62zBafKjIEDymAdyY2RJO52eGBFL9Hb7iIwJLTxFn4hSTCxw1bxNcgZ\nDZ5K1z6sRDGZ/zxlX2mTNYRB/qMEjpOIDt1yUhnJAoGBAOV1a8d4aIHa+oAZwhn5\n0VanqtzbjYHTHrAlcw6TNXxKxO4NUuHhwxG2GLfGsdcXxPKUb0mzN60MznfjW+t/\nCpmXsQtyBXMtLEuxGzGzSn3fAbsuddBh4EbBnEz3xjcO7UiQpnPp0tuEtOAy8N6E\n+6XdDQiSHJaYPvwzOAPcQzjZAoGAZ7ADsAtxLtWf09Y1RFsBwnjE2UbYzWDkvymg\n+qTJSRSF4L8kQsSPbksBoPVHYaHYZ/AbRBGzmtZTgxm762XRyW8uQogOuUnpF6tl\nF2aCmd+PUfQoxi/VHDPh9bil5ugeHc/Px5cxYc8Ug2X5MDeQabIokgKZgE4pddME\nImVaWvECgYA91oqa9YF2ietUS0mdHoxQffbk5es7ITsB999ClyLkko8BuWFwfoMU\naPY7BWS5LIKRz5K1IlZOFftppZ/ZH1p5EWVRbqHn7tAA8ziADZIdeKgr5e3kgEZ7\nbYBb0Q5NdDsw1JsZbPBSEg6cMGjqYm7wbIU1dnER0AcC0BcNAoZx7Q==\n-----END RSA PRIVATE KEY-----"},
          {"name": "JWT_PUBLIC_KEY", "value": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4AryMGWoRkvqHpcOsZxP\nOg75Bpwmu0epn2ENJrnXgkfsv2C5bDXmm0K7CvbqVNDx9WOS13S5iEemoFqhXMNf\nIYPeOYt4wu8h5AUpM1L+cPjzo3hySjIY4z962ppzojP3G0SejCeKq5k9SgfuQRVo\nrlWcxYdykK6fN8uwpYjsi7mXfbSBXjBfI/GL3Wyk5vGgHy/y2rk/uAAEdv2Ip4bp\nOTSI7V+t+hOE+yNCUdUJuySwnTM1VnWZSllRhb9LRz5Mo9gvxF5MpO1J+Q51wSja\nr4K1/eaGqANNNmQm8PzeIpEWmlX3tgbm6jf2RJUvJd4FGv3vAbHsndQUj+4TA8j2\ndwIDAQAB\n-----END PUBLIC KEY-----"},
          {"name": "JWT_KEY_ID", "value": "test-key-1"},
          {"name": "TOKEN_PEPPER", "value": "test-pepper-for-token-hashing"}
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
 
 curl -s http://local
host:3000/auth/test-session -X POST -H "Content-Type: application/json" -
d '{"external_id":"test","email":"test@example.com","organization_name":"
Test Org"}'