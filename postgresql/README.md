## Testing

```bash
docker run -d --rm --name check-postgresql -p 5432:5432 -v $PWD/testdata/:/docker-entrypoint-initdb.d -e POSTGRES_PASSWORD=rootPassword postgres:18.4
sleep 20

CI_POSTGRESQL=true go test -v ./...

docker rm -f check-postgresql 
```
