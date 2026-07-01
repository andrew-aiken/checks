package icmp

import (
	"context"
	"strings"
	"testing"

	"github.com/andrew-aiken/checks"
)

type ValidateTest struct {
	Name            string
	Definition      Definition
	ValidatePassed  bool
	ValidateMessage string
}

type RunTest struct {
	Name                    string
	Definition              Definition
	Result                  checks.Results
	MessageSubstring        string
	ExpectedDetailKeys      []string
	ExpectedDetailExactVals map[string]string
}

var staticConf = checks.StaticConf{
	TeamNumber:    10,
	TeamNumberHex: "a",
}

func TestICMPValidate(t *testing.T) {
	tests := []ValidateTest{
		{
			Name: "InvalidDefinitionMissingHost",
			Definition: Definition{
				AllowPacketLoss: true,
				Count:           1,
				Percent:         100,
				Timeout:         1,
			},
			ValidatePassed:  false,
			ValidateMessage: "Host needs to be defined",
		},
		{
			Name: "NegativeCount",
			Definition: Definition{
				AllowPacketLoss: true,
				Count:           -1,
				Host:            "invalid-hostname-for-checks.invalid",
				Percent:         100,
				Timeout:         1,
			},
			ValidatePassed:  false,
			ValidateMessage: "Count must be larger then 0",
		},
		{
			Name: "InvalidPercentage",
			Definition: Definition{
				AllowPacketLoss: true,
				Count:           1,
				Host:            "invalid-hostname-for-checks.invalid",
				Percent:         127,
				Timeout:         1,
			},
			ValidatePassed:  false,
			ValidateMessage: "Percent must be between 0 and 100",
		},
		{
			Name: "ValidDefinition",
			Definition: Definition{
				AllowPacketLoss: true,
				Count:           1,
				Host:            "invalid-hostname-for-checks.invalid",
				Percent:         100,
				Timeout:         1,
			},
			ValidatePassed:  true,
			ValidateMessage: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			pass, message := tt.Definition.Validate()
			if pass != tt.ValidatePassed {
				t.Fatalf("Validate result does not match expected result(%q) message %t", tt.Name, pass)
			}

			if message != tt.ValidateMessage {
				t.Fatalf("Validate message does not match expected message(%q): got %q want %q", tt.Name, message, tt.ValidateMessage)
			}
		})
	}
}

func TestICMPRun(t *testing.T) {
	tests := []RunTest{
		{
			Name: "FailureTemplateParse",
			Definition: Definition{
				AllowPacketLoss: true,
				Count:           1,
				Host:            "{{",
				Percent:         100,
				Timeout:         1,
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "internal error templating definition",
		},
		{
			Name: "FailureInvalidHost",
			Definition: Definition{
				AllowPacketLoss: true,
				Count:           1,
				Host:            "invalid-hostname-for-checks.invalid",
				Percent:         100,
				Timeout:         1,
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Error creating pinger",
		},
		{
			Name: "FailurePacketCountMismatch",
			Definition: Definition{
				AllowPacketLoss: true,
				Count:           1,
				Host:            "192.0.2.1",
				Percent:         100,
				Timeout:         1,
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring:   "Not all pings made it back!",
			ExpectedDetailKeys: []string{"packets_received", "packets_expected"},
			ExpectedDetailExactVals: map[string]string{
				"packets_expected": "1",
			},
		},
		{
			Name: "FailurePacketLossThreshold",
			Definition: Definition{
				AllowPacketLoss: false,
				Count:           1,
				Host:            "192.0.2.1",
				Percent:         100,
				Timeout:         1,
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring:   "Not all pings made it back!",
			ExpectedDetailKeys: []string{"packetloss_percent"},
		},
		{
			Name: "CloudflareHostCheckPacketLoss",
			Definition: Definition{
				AllowPacketLoss: false,
				Count:           1,
				Host:            "1.1.1.1",
				Percent:         100,
				Timeout:         2,
			},
			Result: checks.Results{
				Passed: true,
			},
		},
		{
			Name: "CloudflareHostCheck",
			Definition: Definition{
				AllowPacketLoss: true,
				Count:   1,
				Host:    "1.1.1.1",
				Percent: 100,
				Timeout: 2,
			},
			Result: checks.Results{
				Passed: true,
			},
		},
		{
			Name: "CloudflareHostCheck",
			Definition: Definition{
				AllowPacketLoss: true,
				Count:   1,
				Host:    "1.1.1.1",
				Percent: 100,
				Timeout: 2,
			},
			Result: checks.Results{
				Passed: true,
			},
		},
	}

	ctx := context.Background()

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
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

			for _, key := range tt.ExpectedDetailKeys {
				if _, ok := result.Details[key]; !ok {
					t.Fatalf("Expected details key %q for check(%q), got details %+v", key, tt.Name, result.Details)
				}
			}

			for key, value := range tt.ExpectedDetailExactVals {
				if result.Details[key] != value {
					t.Fatalf("Expected details[%q] = %q for check(%q), got %q", key, value, tt.Name, result.Details[key])
				}
			}
		})
	}
}
