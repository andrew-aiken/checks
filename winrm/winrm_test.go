package winrm_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/andrew-aiken/checks"
	"github.com/andrew-aiken/checks/winrm"
)

var host string = "54.174.178.120"

var localUsername string = "Administrator"
var localPassword string = "M09@QKqKhIjFMXxKHG1M!NvamNST4*T7"

var domainUsername string = "johndoe"
var domainPassword string = "XHM5pwf-hbz0bzw-hnh2"

func TestWinrm(t *testing.T) {
	if os.Getenv("CI_WINRM") == "" {
		t.Skip("CI_WINRM server test flag not set")
	}

	var staticConfig = checks.StaticConf{}

	tests := []struct {
		Name             string
		Definition       winrm.Definition
		Result           checks.Results
		MessageSubstring string
	}{
		{
			Name: "ValidNTLM",
			Definition: winrm.Definition{
				Host:              host,
				Port:              5985,
				Username:          localUsername,
				Password:          localPassword,
				Command:           "whoami",
				TransportProtocol: "ntlm",
				MatchContent:      true,
				ContentRegex:      `corp\\administrator.*`,
				Encrypted:         false,
			},
			Result: checks.Results{
				Passed: true,
			},
		},
		{
			Name: "ValidKerberos",
			Definition: winrm.Definition{
				Host:              host,
				Port:              5985,
				Command:           "whoami",
				MatchContent:      true,
				Username:          domainUsername,
				Password:          domainPassword,
				ContentRegex:      `corp\\johndoe.*`,
				TransportProtocol: "kerberos",
				Realm:             "CORP.EXAMPLE.ORG",
				Hostname:          "EC2AMAZ-SF7NB60",
				Encrypted:         false,
			},
			Result: checks.Results{
				Passed: true,
			},
		},
		{
			Name: "FailureTemplateParse",
			Definition: winrm.Definition{
				Host:              host,
				Port:              5985,
				Username:          localUsername,
				Password:          localPassword,
				Command:           "whoami",
				TransportProtocol: "{{",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "internal error templating definition",
		},
		{
			Name: "InvalidCommand",
			Definition: winrm.Definition{
				Host:     host,
				Port:     5985,
				Username: localUsername,
				Password: localPassword,
				Command:  "dne.exe",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "command returned error: 'dne.exe' is not recognized as an internal or external command",
		},
		{
			Name: "InvalidRegex",
			Definition: winrm.Definition{
				Host:         host,
				Port:         5985,
				Username:     localUsername,
				Password:     localPassword,
				Command:      "whoami",
				MatchContent: true,
				ContentRegex: `[a-z`,
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Error compiling regex string",
		},
		{
			Name: "RegexMatchFail",
			Definition: winrm.Definition{
				Host:         host,
				Port:         5985,
				Username:     localUsername,
				Password:     localPassword,
				Command:      "whoami",
				MatchContent: true,
				ContentRegex: `corp\\dummy.*`,
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Matching content not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			ctx := context.Background()
			timeoutContext, cxtCancel := context.WithTimeout(ctx, 10*time.Second)
			defer cxtCancel()

			result := tt.Definition.Run(timeoutContext, staticConfig)

			if result.Passed != tt.Result.Passed {
				t.Fatalf("Check result does not match expected result(%q) message '%t'", tt.Name, result.Passed)
			}

			if tt.MessageSubstring != "" && !strings.Contains(result.Message, tt.MessageSubstring) {
				t.Fatalf("Expected message substring %q for check(%q), got message %q", tt.MessageSubstring, tt.Name, result.Message)
			}
		})
	}
}

func TestValidateWINRM(t *testing.T) {
	tests := []struct {
		Name            string
		Definition      winrm.Definition
		ValidateMessage string
	}{
		{
			Name: "Valid",
			Definition: winrm.Definition{
				Host:              "dc.neccdl.org",
				Username:          "dummy",
				Password:          "dummy",
				TransportProtocol: "ntlm",
			},
		},
		{
			Name: "MissingHost",
			Definition: winrm.Definition{
				// Host:              "dc.neccdl.org",
				Username:          "dummy",
				Password:          "dummy",
				TransportProtocol: "ntlm",
			},
			ValidateMessage: "Host needs to be defined",
		},
		{
			Name: "MissingUsername",
			Definition: winrm.Definition{
				Host: "dc.neccdl.org",
				// Username:          "dummy",
				Password:          "dummy",
				TransportProtocol: "ntlm",
			},
			ValidateMessage: "Username needs to be defined",
		},
		{
			Name: "MissingPassword",
			Definition: winrm.Definition{
				Host:     "dc.neccdl.org",
				Username: "dummy",
				// Password:          "dummy",
				TransportProtocol: "ntlm",
			},
			ValidateMessage: "Password needs to be defined",
		},
		{
			Name: "InvalidTransportProtocol",
			Definition: winrm.Definition{
				Host:              "dc.neccdl.org",
				Username:          "dummy",
				Password:          "dummy",
				TransportProtocol: "foo",
			},
			ValidateMessage: "Invalid transport protocol option",
		},
		{
			Name: "KerberosParams",
			Definition: winrm.Definition{
				Host:              "dc.neccdl.org",
				Username:          "dummy",
				Password:          "dummy",
				TransportProtocol: "kerberos",
			},
			ValidateMessage: "When running in Kerberos mode hostname & realm must be set",
		},
		{
			Name: "InvalidRegex",
			Definition: winrm.Definition{
				Host:         "dc.neccdl.org",
				Username:     "dummy",
				Password:     "dummy",
				Command:      "whoami",
				ContentRegex: "[a-z",
				MatchContent: true,
			},
			ValidateMessage: "Failed to compile regex",
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
