package helper

import (
	"fmt"

	"github.com/andrew-aiken/checks/dns"
	"github.com/andrew-aiken/checks/ftp"
	"github.com/andrew-aiken/checks/http"
	"github.com/andrew-aiken/checks/icmp"
	"github.com/andrew-aiken/checks/ldap"
	"github.com/andrew-aiken/checks/mysql"
	"github.com/andrew-aiken/checks/noop"
	"github.com/andrew-aiken/checks/postgresql"
	"github.com/andrew-aiken/checks/rdp"
	"github.com/andrew-aiken/checks/smb"
	"github.com/andrew-aiken/checks/smtp"
	"github.com/andrew-aiken/checks/ssh"
	"github.com/andrew-aiken/checks/tcp"
	"github.com/andrew-aiken/checks/winrm"
)

// NewDefinition takes in a check type and returns its definition
func NewDefinition(checkType string) (definitionType any, err error) {
	switch checkType {
	case "dns":
		return &dns.Definition{}, nil
	case "ftp":
		return &ftp.Definition{}, nil
	case "http":
		return &http.Definition{}, nil
	case "icmp":
		return &icmp.Definition{}, nil
	case "ldap":
		return &ldap.Definition{}, nil
	case "mysql":
		return &mysql.Definition{}, nil
	case "noop":
		return &noop.Definition{}, nil
	case "postgresql":
		return &postgresql.Definition{}, nil
	case "rdp":
		return &rdp.Definition{}, nil
	case "smb":
		return &smb.Definition{}, nil
	case "smtp":
		return &smtp.Definition{}, nil
	case "ssh":
		return &ssh.Definition{}, nil
	case "tcp":
		return &tcp.Definition{}, nil
	case "winrm":
		return &winrm.Definition{}, nil
	default:
		return nil, fmt.Errorf("unknown check type %q", checkType)
	}
}
