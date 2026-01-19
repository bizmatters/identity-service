kubectl get pods -n platform-identity
kubectl get pods -n platform-identity
kubectl logs -n platform-identity deployment/identity-service --tail=20

docker build -t identity-service:ci-test .
kind load docker-image identity-service:ci-test --name zerotouch-preview

kubectl run integration-test-oidc --image=identity-service:ci-test --rm -i --restart=Never -n platform-identity --overrides='

kubectl port-forward -n platform-identity svc/identity-service 3000:3000 &

curl -s http://localhost:3000/auth/login
curl -s "http://localhost:3000/auth/login?redirect_uri=https://localhost:3000"
