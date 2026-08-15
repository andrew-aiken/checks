package smtp_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/andrew-aiken/checks"
	"github.com/andrew-aiken/checks/smtp"
)

func TestSMTP(t *testing.T) {
	// This test relies on an external smtp server
	if os.Getenv("CI_SMTP") == "" {
		t.Skip("CI_SMTP test flag not set")
	}

	var port uint16 = 1025
	host := "localhost"
	username := "user"
	password := "password"

	staticConfig := checks.StaticConf{}

	tests := []struct {
		Name             string
		Definition       smtp.Definition
		Result           checks.Results
		MessageSubstring string
	}{
		{
			Name: "Valid",
			Definition: smtp.Definition{
				Host:      host,
				Port:      port,
				Username:  username,
				Password:  password,
				Encrypted: false,
				Subject:   "foo",
				Body:      "Hello World",
				Sender:    "sender@neccdl.org",
				Recipient: "receiver@neccdl.org",
			},
			Result: checks.Results{
				Passed: true,
			},
		},
		{
			Name: "FailTLS",
			Definition: smtp.Definition{
				Host:           host,
				Port:           port,
				Username:       username,
				Password:       password,
				Encrypted:      true,
				SkipVerifyCert: true,
				Subject:        "foo",
				Body:           "Hello World",
				Sender:         "sender@neccdl.org",
				Recipient:      "receiver@neccdl.org",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Failed to establish encrypted session with localhost:1025: smtp: server doesn't support STARTTLS",
		},
		{
			Name: "FailAuthentication",
			Definition: smtp.Definition{
				Host:      host,
				Port:      port,
				Username:  username,
				Password:  "wrongPasswd",
				Sender:    "sender@neccdl.org",
				Recipient: "receiver@neccdl.org",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Failed to authenticate as user: SMTP error 535: Authentication credentials invalid",
		},
		{
			Name: "FailureTemplateParse",
			Definition: smtp.Definition{
				Host:      host,
				Sender:    "{{",
				Recipient: "receiver@neccdl.org",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "internal error templating definition",
		},
		{
			Name: "FailedConnection",
			Definition: smtp.Definition{
				Host:      host,
				Port:      port + 1,
				Sender:    "sender@neccdl.org",
				Recipient: "receiver@neccdl.org",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Failed to connect to SMTP",
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

func TestSMTPValidate(t *testing.T) {
	tests := []struct {
		Name            string
		Definition      smtp.Definition
		ValidateMessage string
	}{
		{
			Name: "Valid",
			Definition: smtp.Definition{
				Host:      "smtp.neccdl.org",
				Subject:   "Subject",
				Body:      "Hello World",
				Sender:    "sender@neccdl.org",
				Recipient: "receiver@neccdl.org",
			},
		},
		{
			Name: "MissingHost",
			Definition: smtp.Definition{
				// Host:           "smtp.neccdl.org",
				Subject:   "Subject",
				Body:      "Hello World",
				Sender:    "sender@neccdl.org",
				Recipient: "receiver@neccdl.org",
			},
			ValidateMessage: "Host needs to be defined",
		},
		{
			Name: "MissingSender",
			Definition: smtp.Definition{
				Host:    "smtp.neccdl.org",
				Subject: "Subject",
				Body:    "Hello World",
				// Sender:         "sender@neccdl.org",
				Recipient: "receiver@neccdl.org",
			},
			ValidateMessage: "Sender needs to be defined",
		},
		{
			Name: "MissingRecipient",
			Definition: smtp.Definition{
				Host:    "smtp.neccdl.org",
				Subject: "Subject",
				Body:    "Hello World",
				Sender:  "sender@neccdl.org",
				// Recipient:      "receiver@neccdl.org",
			},
			ValidateMessage: "Recipient needs to be defined",
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
