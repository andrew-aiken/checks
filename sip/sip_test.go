package sip_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/andrew-aiken/checks"
	"github.com/andrew-aiken/checks/sip"

	gosip "github.com/emiago/sipgo/sip"
)

func TestSIPValidate(t *testing.T) {
	tests := []struct {
		Name            string
		Definition      sip.Definition
		ValidateMessage string
	}{
		{
			Name: "Valid",
			Definition: sip.Definition{
				Host: "sip.neccdl.org",
			},
		},
		{
			Name:            "MissingHost",
			Definition:      sip.Definition{},
			ValidateMessage: "Host needs to be defined",
		},
		{
			Name: "InvalidTransport",
			Definition: sip.Definition{
				Host:      "sip.neccdl.org",
				Transport: "sctp",
			},
			ValidateMessage: "Invalid SIP transport protocol specified",
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

// TestSIP attempts to register and place calls against a real SIP PBX
func TestSIP(t *testing.T) {
	if os.Getenv("CI_SIP") == "" {
		t.Skip("CI_SIP test flag not set")
	}

	gosip.SIPDebug = os.Getenv("SIP_DEBUG") == "true"

	staticConfig := checks.StaticConf{}

	host := "sip.neccdl.org"
	username := "1001"
	password := "abc123"
	callee := "1002"
	transport := "udp"

	tests := []struct {
		Name             string
		Definition       sip.Definition
		Result           checks.Results
		MessageSubstring string
	}{
		{
			Name: "Register",
			Definition: sip.Definition{
				Host:      host,
				Port:      5060,
				Username:  username,
				Password:  password,
				Transport: transport,
			},
			Result: checks.Results{
				Passed: true,
			},
		},
		{
			Name: "AnonymousCall",
			Definition: sip.Definition{
				Host:      host,
				Port:      5060,
				Transport: transport,
				Callee:    callee,
			},
			Result: checks.Results{
				Passed: true,
			},
		},
		{
			Name: "AuthenticatedCall",
			Definition: sip.Definition{
				Host:      host,
				Port:      5060,
				Username:  username,
				Password:  password,
				Transport: transport,
				Callee:    callee,
			},
			Result: checks.Results{
				Passed: true,
			},
		},
		{
			Name: "FailureTemplateParse",
			Definition: sip.Definition{
				Host: "{{",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "internal error templating definition",
		},
		{
			Name: "WrongPassword",
			Definition: sip.Definition{
				Host:      host,
				Port:      5060,
				Username:  username,
				Password:  "wrongPassword",
				Transport: transport,
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Failed to register client",
		},
		{
			Name: "FailedConnection",
			Definition: sip.Definition{
				Host:      host,
				Port:      5061,
				Username:  username,
				Password:  password,
				Transport: transport,
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "did not get registration response",
		},
		{
			Name: "AnonymousCallRejectedForOtherReason",
			Definition: sip.Definition{
				Host:      host,
				Port:      5060,
				Transport: transport,
				Callee:    username,
			},
			Result: checks.Results{
				Passed: true,
			},
		},
		{
			Name: "IncorrectPort",
			Definition: sip.Definition{
				Host:      host,
				Port:      5099,
				Transport: transport,
				Callee:    callee,
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "got no response at all",
		},
		{
			Name: "IncorrectHost",
			Definition: sip.Definition{
				Host:      "this-host-does-not-exist.invalid",
				Transport: transport,
				Callee:    callee,
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "failed to send invite",
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			if tt.Definition.Timeout == 0 {
				tt.Definition.Timeout = 3
			}

			ctx := context.Background()

			result := tt.Definition.Run(ctx, staticConfig)

			if result.Passed != tt.Result.Passed {
				t.Fatalf("Check does not match expected result: test(%q) got %t", tt.Name, result.Passed)
			}

			if tt.MessageSubstring != "" && !strings.Contains(result.Message, tt.MessageSubstring) {
				t.Fatalf("Expected message substring %q for check(%q), got message %q", tt.MessageSubstring, tt.Name, result.Message)
			}
		})
	}
}
