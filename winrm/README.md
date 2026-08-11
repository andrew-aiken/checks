

```powershell
winrm quickconfig -force
winrm set winrm/config/service '@{AllowUnencrypted="true"}'

netsh advfirewall firewall add rule name="WinRM-HTTP" dir=in localport=5985 protocol=TCP action=allow

Get-Service WinRM
```
