# Checks

![License](https://img.shields.io/badge/License-GLP%203.0-blue.svg)
![GitHub Release](https://img.shields.io/github/v/release/andrew-aiken/check)
![Tests](https://img.shields.io/github/actions/workflow/status/andrew-aiken/checks/gotest)

---

This project provides unified checks that can be consumed across a wide variety of scoring systems.

### Features

- Service Agnostic
- Leading amount of supported check types
- Comprehensive check validation & tests
- Documentation (wip)

## Supported Checks

| Name                      | [Quotient](https://github.com/dbaseqp/Quotient) | [Scorestack](https://github.com/scorestack/scorestack) | [Scorify](https://github.com/Scorify/Scorify) | Checks |
| :------------------------ | :---------------------------------------------: | :----------------------------------------------------: | :-------------------------------------------: | :----: |
| [DNS](dns/)               |                       ✅                        |                           ✅                           |                      ✅                       |   ✅   |
| [FTP](ftp/)               |                       ✅                        |                           ✅                           |                      ✅                       |   ✅   |
| [GIT](git/)               |                       ⭕                        |                           ✅                           |                      ⭕                       |   ✅   |
| [HTTP](http/)             |                       ✅                        |                           ✅                           |                      ✅                       |   ✅   |
| [ICMP](icmp/)             |                       ✅                        |                           ✅                           |                      ✅                       |   ✅   |
| [IMAP](imap/)             |                       ✅                        |                           ⭕                           |                      ✅                       |   ✅   |
| [Kubernetes](kubernetes/) |                       ⭕                        |                           ⭕                           |                      ⭕                       |   ✅   |
| [LDAP](ldap/)             |                       ✅                        |                           ✅                           |                      ✅                       |   ✅   |
| MSSQL                     |                       ⭕                        |                           ✅                           |                      ⭕                       |   ⭕   |
| [MySQL](mysql/)           |                       ✅                        |                           ✅                           |                      ✅                       |   ✅   |
| [POP3](pop3/)             |                       ✅                        |                           ⭕                           |                      ⭕                       |   ✅   |
| [PostgreSQL](postgresql/) |                       ⭕                        |                           ✅                           |                      ⭕                       |   ✅   |
| [RDP](rdp/)               |                       ⭕                        |                           ⭕                           |                      ⭕                       |   ✅   |
| [SMB](smb/)               |                       ✅                        |                           ✅                           |                      ✅                       |   ✅   |
| [SMTP](smtp/)             |                       ✅                        |                           ✅                           |                      ✅                       |   ✅   |
| [SSH](ssh/)               |                       ✅                        |                           ✅                           |                      ✅                       |   ✅   |
| [TCP](tcp/)               |                       ✅                        |                           ⭕                           |                      ✅                       |   ✅   |
| [VNC](vnc/)               |                       ✅                        |                           ✅                           |                      ⭕                       |   ✅   |
| [WINRM](winrm/)           |                       ✅                        |                           ✅                           |                      ✅                       |   ✅   |
| XMPP                      |                       ⭕                        |                           ✅                           |                      ⭕                       |   ⭕   |

## Contributing

### Testing

The majority of checks have self contained servers they test against.
Services that have larger dependencies (windows, databases, mail) have test flags, refer to the checks README for testing instructions.

```bash
# Verify formatting is correct
gofmt -l .

# Lint
golangci-lint run

# Check for security findings
# Findings are allowed to be suppressed, checks can perform insecure connections
gosec ./...

# Verify the tests all are functioning or just target a specific check being modified
go test -v -race ./...
```

#### Coverage

Checks should aim to have ~80% or more test coverage

```bash
go test -coverprofile=coverage.out ./... && go tool cover -html=coverage.out
```
