# RDP Check
The RDP Check attempts a connection only.
It does not run any commands or validates anything on the host.

## TODO
- Validate check works with domain users

## Testing
Requires external RDP server to fully test.

```bash
CI_RDP=true go test ./... -v --count=1 --cover
```
