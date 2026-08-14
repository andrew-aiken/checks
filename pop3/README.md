# POP3 Check

## Testing

```bash
docker run --rm -d \
  --name=mailpit \
  -p 8025:8025 \
  -p 1025:1025 \
  -p 1110:1110 \
  -e MP_POP3_AUTH="user:password" \
  -e MP_SMTP_AUTH="user:password" \
  axllent/mailpit \
  --smtp-auth-allow-insecure \
  --pop3-tls-cert sans:localhost --pop3-tls-key sans:localhost \
  --smtp-tls-cert sans:localhost --smtp-tls-key sans:localhost
  

sleep 3

CI_POP3=true go test ./... -v --cover --count=1

docker rm -f mailpit
```
