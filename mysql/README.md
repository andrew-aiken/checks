## Testing

```bash
docker run -d --rm --name check-mysql -p 3306:3306 -v $PWD/testdata/:/docker-entrypoint-initdb.d -e MYSQL_ROOT_PASSWORD=rootPassword mysql:8.4.11
sleep 20

CI_MYSQL=true go test -v ./...

docker rm -f check-mysql 
```
