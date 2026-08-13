package dns_test

import (
	"context"
	"strings"
	"testing"

	"github.com/andrew-aiken/checks"
	"github.com/andrew-aiken/checks/dns"
)

type ValidateTest struct {
	Name            string
	Definition      dns.Definition
	ValidateMessage string
}

type RunTest struct {
	Name             string
	Definition       dns.Definition
	Result           checks.Results
	MessageSubstring string
}

var staticConf = checks.StaticConf{
	TeamNumber:    10,
	TeamNumberHex: "a",
}

func TestDNSValidate(t *testing.T) {
	tests := []ValidateTest{
		{
			Name: "MissingServer",
			Definition: dns.Definition{
				// Server: "",
				Fqdn:           "example.com",
				ExpectedResult: "DNE",
				Port:           53,
				RecordType:     "A",
			},
			ValidateMessage: "Server needs to be defined",
		},
		{
			Name: "MissingFqdn",
			Definition: dns.Definition{
				Server: "1.1.1.1",
				// Fqdn: "",
				ExpectedResult: "DNE",
				Port:           53,
				RecordType:     "A",
			},
			ValidateMessage: "FQDN needs to be defined",
		},
		{
			Name: "MissingResult",
			Definition: dns.Definition{
				Server: "1.1.1.1",
				Fqdn:   "example.com",
				// ExpectedResult: "",
				Port:       53,
				RecordType: "A",
			},
			ValidateMessage: "Expected result needs to be defined",
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

func TestDNSRun(t *testing.T) {
	tests := []RunTest{
		{
			Name: "InvalidRecordType",
			Definition: dns.Definition{
				Server:         "1.1.1.1",
				Fqdn:           "example.com",
				ExpectedResult: "dummy",
				RecordType:     "DNE",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Unknown record type",
		},
		{
			Name: "InvalidRegex",
			Definition: dns.Definition{
				Server:         "1.1.1.1",
				Fqdn:           "example.com",
				ExpectedResult: "{{",
				RecordType:     "DNE",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "internal error templating definition",
		},
		{
			Name: "BadQuery",
			Definition: dns.Definition{
				Server:         "1.1.1.1.1",
				Fqdn:           "example.com",
				ExpectedResult: "dummy",
				RecordType:     "A",
				Port:           53,
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Problem sending query to 1.1.1.1.1 : dial udp: lookup 1.1.1.1.1: no such host",
		},
		{
			Name: "NoResults",
			Definition: dns.Definition{
				Server:         "1.1.1.1",
				Fqdn:           "dne.neccdl.org",
				ExpectedResult: "dne",
				RecordType:     "A",
				Port:           53,
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "No records received from 1.1.1.1",
		},
		{
			Name: "WrongResults",
			Definition: dns.Definition{
				Server:         "1.1.1.1",
				Fqdn:           "one.one.one.one",
				ExpectedResult: "dne",
				RecordType:     "A",
				Port:           53,
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Incorrect Records Returned",
		},
		{
			Name: "Validate",
			Definition: dns.Definition{
				Server:         "1.1.1.1",
				Fqdn:           "one.one.one.one",
				ExpectedResult: "1.1.1.1",
				RecordType:     "A",
				Port:           53,
			},
			Result: checks.Results{
				Passed: true,
			},
		},
	}

	ctx := context.Background()

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			// Default values are assigned when parsing from json only
			if tt.Definition.Timeout == 0 {
				tt.Definition.Timeout = 10
			}

			pass, message := tt.Definition.Validate()
			if !pass {
				t.Fatalf("Failed to validate check(%q) message %s", tt.Name, message)
			}

			result := tt.Definition.Run(ctx, staticConf)

			if result.Passed != tt.Result.Passed {
				t.Fatalf("Check result does not match expected result(%q) message %t", tt.Name, result.Passed)
			}

			if tt.MessageSubstring != "" && !strings.Contains(result.Message, tt.MessageSubstring) {
				t.Fatalf("Expected message substring %q for check(%q), got message %q", tt.MessageSubstring, tt.Name, result.Message)
			}
		})
	}
}
