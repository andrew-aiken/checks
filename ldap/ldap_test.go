package ldap_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/andrew-aiken/checks"
	"github.com/andrew-aiken/checks/ldap"
)

func TestLDAP(t *testing.T) {
	if os.Getenv("CI_LDAP") == "" {
		t.Skip("CI_LDAP test flag not set")
	}

	staticConfig := checks.StaticConf{}

	host := "127.0.0.1"
	var port uint16 = 3890
	domain := "example.org"
	username := "cn=admin,dc=example,dc=org"
	password := "adminPass"

	tests := []struct {
		Name             string
		Definition       ldap.Definition
		Result           checks.Results
		MessageSubstring string
	}{
		{
			Name: "Valid",
			Definition: ldap.Definition{
				Host:           host,
				Port:           port,
				Domain:         domain,
				Username:       username,
				Password:       password,
				Encrypted:      true,
				SkipVerifyCert: true,
			},
			Result: checks.Results{
				Passed: true,
			},
		},
		{
			Name: "FailureTemplateParse",
			Definition: ldap.Definition{
				Host:     host,
				Port:     port,
				Username: username,
				Password: "{{",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "internal error templating definition",
		},
		{
			Name: "FailedConnection",
			Definition: ldap.Definition{
				Host:     host,
				Port:     port + 1,
				Username: username,
				Password: password,
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: `Failed to dial ldap ldap://127.0.0.1:3891: LDAP Result Code 200 "Network Error": dial tcp 127.0.0.1:3891: connect: connection refused`,
		},
		{
			Name: "FailedTLS",
			Definition: ldap.Definition{
				Host:      host,
				Port:      port,
				Username:  username,
				Password:  password,
				Domain:    "dummy.org",
				Encrypted: true,
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: `Failed to setup TLS session: LDAP Result Code 200 "Network Error": TLS handshake failed (tls: failed to verify certificate: x509: certificate signed by unknown authority)`,
		},
		{
			Name: "InvalidAddressFormat",
			Definition: ldap.Definition{
				Host:     host,
				Port:     port,
				Username: "DSN",
				Domain:   domain,
				Password: password,
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: `Failed to login with user: LDAP Result Code 34 "Invalid DN Syntax": invalid DN`,
		},
		{
			Name: "FailedAuth",
			Definition: ldap.Definition{
				Host:     host,
				Port:     port,
				Username: "cn=dummy,dc=example,dc=org",
				Password: password,
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: `Failed to login with user: LDAP Result Code 49 "Invalid Credentials"`,
		},
		{
			Name: "FailedPasswordLessAuth",
			Definition: ldap.Definition{
				Host:     host,
				Port:     port,
				Username: "cn=dummy,dc=example,dc=org",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: `Failed to login with user: LDAP Result Code 53 "Unwilling To Perform": unauthenticated bind (DN with no password) disallowed`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			ctx := context.Background()
			timeoutContext, cxtCancel := context.WithTimeout(ctx, 3*time.Second)
			defer cxtCancel()

			result := tt.Definition.Run(timeoutContext, staticConfig)

			if result.Passed != tt.Result.Passed {
				t.Fatalf("Check does not match expected result: test(%q) got %t", tt.Name, result.Passed)
			}

			if tt.MessageSubstring != "" && !strings.Contains(result.Message, tt.MessageSubstring) {
				t.Fatalf("Expected message substring %q for check(%q), got message %q", tt.MessageSubstring, tt.Name, result.Message)
			}
		})
	}
}

func TestLDAPValidate(t *testing.T) {
	tests := []struct {
		Name            string
		Definition      ldap.Definition
		ValidateMessage string
	}{
		{
			Name: "Valid",
			Definition: ldap.Definition{
				Host:     "ldap.neccdl.org",
				Username: "cn=dummy,dc=example,dc=org",
			},
		},
		{
			Name: "MissingHost",
			Definition: ldap.Definition{
				// Host:  "ldap.neccdl.org",
				Username: "cn=dummy,dc=example,dc=org",
			},
			ValidateMessage: "Host needs to be defined",
		},
		{
			Name: "MissingUsername",
			Definition: ldap.Definition{
				Host: "ldap.neccdl.org",
				// Username: "cn=dummy,dc=example,dc=org",
			},
			ValidateMessage: "Username needs to be defined",
		},
		{
			Name: "DomainForEncryption",
			Definition: ldap.Definition{
				Host:      "ldap.neccdl.org",
				Username:  "cn=dummy,dc=example,dc=org",
				Encrypted: true,
			},
			ValidateMessage: "Domain needs to be set when using encryption",
		},
		{
			Name: "InvalidConnector",
			Definition: ldap.Definition{
				Host:     "ldap.neccdl.org",
				Username: "dummy",
			},
			ValidateMessage: "Login needs to be set as LDIF or UPN format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			_, message := tt.Definition.Validate()
			if message != tt.ValidateMessage {
				t.Fatalf("Validate message does not match expected message(%q): got %q want %q", tt.Name, message, tt.ValidateMessage)
			}
		})
	}
}
