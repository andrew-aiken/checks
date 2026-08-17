# Kubernetes Check

## Test
```bash
# https://minikube.sigs.k8s.io/docs/tutorials/token-auth-file/
mkdir -p ~/.minikube/files/etc/ca-certificates/
echo "token123,user,1000" > ~/.minikube/files/etc/ca-certificates/token.csv

minikube start --kubernetes-version=1.36 --nodes=0 --extra-config=apiserver.token-auth-file=/etc/ca-certificates/token.csv

export CI_KUBERNETES_PORT=`docker inspect -f '{{(index (index .NetworkSettings.Ports "8443/tcp") 0).HostPort}}' minikube`
export CI_KUBERNETES_CA=`cat ~/.minikube/ca.crt | base64`
export CI_KUBERNETES_KEY=`cat ~/.minikube/profiles/minikube/client.key | base64`
export CI_KUBERNETES_CERT=`cat ~/.minikube/profiles/minikube/client.crt | base64`

CI_KUBERNETES=true go test ./... --count=1 --cover -race

minikube delete
```
