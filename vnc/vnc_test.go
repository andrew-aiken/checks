package vnc_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/andrew-aiken/checks"
	"github.com/andrew-aiken/checks/vnc"
)

var host string = "localhost"
var password string = "vncpassword"
var port uint16 = 5901

func TestVNC(t *testing.T) {
	if os.Getenv("CI_VNC") == "" {
		t.Skip("CI_VNC test flag not set")
	}

	staticConfig := checks.StaticConf{}

	tests := []struct {
		Name             string
		Definition       vnc.Definition
		Result           checks.Results
		MessageSubstring string
	}{
		{
			Name: "Valid",
			Definition: vnc.Definition{
				Host:          host,
				Port:          port,
				Password:      password,
				MatchHostname: "test-vnc",
			},
			Result: checks.Results{
				Passed: true,
			},
		},
		{
			Name: "FailedAuth",
			Definition: vnc.Definition{
				Host:     host,
				Port:     port,
				Password: "dummy",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Error negotiating connection to VNC host: SecurityResult handshake failed: Authentication failure",
		},
		{
			Name: "FailDial",
			Definition: vnc.Definition{
				Host:     host,
				Port:     port + 1,
				Password: password,
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Error connecting to VNC host: dial tcp [::1]:5902: connect: connection refused",
		},
		{
			Name: "HostnameMismatch",
			Definition: vnc.Definition{
				Host:          host,
				Port:          port,
				Password:      password,
				MatchHostname: "serverHostname",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Hostname does not match, got test-vnc, expected serverHostname",
		},
		{
			Name: "FailureTemplateParse",
			Definition: vnc.Definition{
				Host:     host,
				Port:     port,
				Password: "{{",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "internal error templating definition",
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			ctx := context.Background()
			timeoutContext, cxtCancel := context.WithTimeout(ctx, 30*time.Second)
			defer cxtCancel()

			result := tt.Definition.Run(timeoutContext, staticConfig)

			if result.Passed != tt.Result.Passed {
				t.Fatalf("Check result does not match expected result(%q) message %t", tt.Name, result.Passed)
			}

			if tt.MessageSubstring != "" && !strings.Contains(result.Message, tt.MessageSubstring) {
				t.Fatalf("Expected message substring %q for check(%q), got message %q", tt.MessageSubstring, tt.Name, result.Message)
			}
		})
	}
}

func TestVNCValidate(t *testing.T) {
	tests := []struct {
		Name            string
		Definition      vnc.Definition
		ValidateMessage string
	}{
		{
			Name: "Valid",
			Definition: vnc.Definition{
				Host:     "vnc.neccdl.org",
				Password: "password132",
			},
		},
		{
			Name: "MissingHost",
			Definition: vnc.Definition{
				// Host:      "vnc.neccdl.org",
				Password: "password132",
			},
			ValidateMessage: "Host needs to be defined",
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
