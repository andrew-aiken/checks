# SMTP

## Tests

```bash
docker run -d --rm \
  --name=mailpit \
  -p 8025:8025 \
  -p 1025:1025 \
  -v $PWD/testdata/:/files \
  axllent/mailpit \
  --smtp-auth-allow-insecure \
  --smtp-auth-file /files/smtpUsers.txt

sleep 3

CI_SMTP=true go test ./... -v --cover

docker rm -f mailpit
```
