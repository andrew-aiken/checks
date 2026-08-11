

```powershell
winrm quickconfig -force

netsh advfirewall firewall add rule name="WinRM-HTTP" dir=in localport=5985 protocol=TCP action=allow

Get-Service WinRM
```
