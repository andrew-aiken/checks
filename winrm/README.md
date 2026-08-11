# Check WINRM

## Future Ideas
- The provider supports SSH dialer, could be used for winrm connection dialer
- Support certificates in winrm client endpoint creation

## Testing
Testing this is a pain...

I built out a domain control on AWS ([guide](https://medium.com/@galazkaryan/create-an-active-directory-environment-on-aws-ec2-mastery-454b1af57a8c)), but takes a lot of configuring and tweaking to get right.

WinRM and AD needs to be setup to properly test NTLM and Kerberos. Additionally some group policies were modified to allow AD user to connect to the AD machine.

```powershell
winrm quickconfig -force
winrm set winrm/config/service '@{AllowUnencrypted="true"}'

netsh advfirewall firewall add rule name="WinRM-HTTP" dir=in localport=5985 protocol=TCP action=allow

Get-Service WinRM
```

Once the server is setup run the got test

```bash
CI_WINRM=true go test ./... -v --count=1
```
