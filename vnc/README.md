# VNC Check

## Test
https://github.com/ConSol/docker-headless-vnc-container

```bash
docker run --rm -d --hostname test-vnc -p 5901:5901 -p 6901:6901 -e VNC_PW=vncpassword consol/rocky-xfce-vnc
sleep 3

CI_VNC=true go test ./... --count=1 --cover -race

docker rm -f test-vnc
```
