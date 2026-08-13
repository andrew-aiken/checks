# SMB Check

## Testing

Relies on external [SMB server](https://github.com/dockur/samba) for testing.

```bash
docker run -it -d --rm --name samba -p 445:445 -e "NAME=Data" -e "USER=samba" -e "PASS=secret" -v "$PWD/testdata:/storage" docker.io/dockurr/samba

sleep 3

CI_SMB=true go test ./... -v --count=1 --cover

docker rm -f samba
```
