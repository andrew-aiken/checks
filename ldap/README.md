# LDAP Check

## Test
```bash
docker run --name openldap --rm -d -p 3890:389 -p 6360:636 \
  --hostname ldap.example.com \
	--env LDAP_ORGANISATION="Example Company" \
	--env LDAP_DOMAIN="example.org" \
	--env LDAP_ADMIN_PASSWORD="adminPass" \
	--env LDAP_TLS_VERIFY_CLIENT="try" \
	osixia/openldap:1.5.0

sleep 3

CI_LDAP=true go test ./... -v --count=1

docker rm -f openldap
```

## Coverage
Current tests missing coverage of passwordless authentication
