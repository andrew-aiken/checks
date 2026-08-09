```bash
cd checks/mysql/testdata

docker run -d --rm --name check-mysql -p 3306:3306 -v $PWD:/docker-entrypoint-initdb.d -e MYSQL_ROOT_PASSWORD=rootPassword mysql:8.4.11

CI_MYSQL=true go test -v ./...

docker rm -f check-mysql 
```
