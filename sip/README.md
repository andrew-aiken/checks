## SIP Check

Future features:
- TLS

## Testing

This test relies on an external SIP server to function.

```bash
CI_SIP=true go test ./... -v --cover
```
