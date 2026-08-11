package helper_test

import (
	"fmt"
	"testing"

	"github.com/andrew-aiken/checks/dns"
	"github.com/andrew-aiken/checks/ftp"
	"github.com/andrew-aiken/checks/helper"
	"github.com/andrew-aiken/checks/http"
	"github.com/andrew-aiken/checks/icmp"
	"github.com/andrew-aiken/checks/ldap"
	"github.com/andrew-aiken/checks/mysql"
	"github.com/andrew-aiken/checks/noop"
	"github.com/andrew-aiken/checks/postgresql"
	"github.com/andrew-aiken/checks/smb"
	"github.com/andrew-aiken/checks/smtp"
	"github.com/andrew-aiken/checks/ssh"
	"github.com/andrew-aiken/checks/tcp"
	"github.com/andrew-aiken/checks/winrm"
)

type Test struct {
	checkType string
	want      any
	wantErr   bool
}

func TestNewDefinition(t *testing.T) {
	tests := []Test{
		{"dns", &dns.Definition{}, false},
		{"ftp", &ftp.Definition{}, false},
		{"http", &http.Definition{}, false},
		{"icmp", &icmp.Definition{}, false},
		{"ldap", &ldap.Definition{}, false},
		{"mysql", &mysql.Definition{}, false},
		{"noop", &noop.Definition{}, false},
		{"postgresql", &postgresql.Definition{}, false},
		{"smb", &smb.Definition{}, false},
		{"smtp", &smtp.Definition{}, false},
		{"ssh", &ssh.Definition{}, false},
		{"tcp", &tcp.Definition{}, false},
		{"winrm", &winrm.Definition{}, false},
		{"unknown", nil, true},
		{"", nil, true},
	}

	for _, test := range tests {
		t.Run(test.checkType, func(t *testing.T) {
			got, err := helper.NewDefinition(test.checkType)
			if (err != nil) != test.wantErr {
				t.Fatalf("NewDefinition(%q) error = %v, wantErr %v", test.checkType, err, test.wantErr)
			}
			if test.wantErr {
				return
			}
			if got == nil {
				t.Fatalf("NewDefinition(%q) returned nil, want %T", test.checkType, test.want)
			}
			gotType := fmt.Sprintf("%T", got)
			wantType := fmt.Sprintf("%T", test.want)
			if gotType != wantType {
				t.Errorf("NewDefinition(%q) type = %s, want %s", test.checkType, gotType, wantType)
			}
		})
	}
}
