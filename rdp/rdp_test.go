package rdp_test

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/andrew-aiken/checks"
	"github.com/andrew-aiken/checks/rdp"
)

var host string = "3.81.127.110"
var username string = "Administrator"
var password string = "rdpAdminPasswd"

func TestRDP(t *testing.T) {
	if os.Getenv("CI_RDP") == "" {
		t.Skip("CI_RDP test flag not set")
	}

	staticConfig := checks.StaticConf{}

	opts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}
	handler := slog.NewTextHandler(os.Stdout, opts)
	logger := slog.New(handler)
	slog.SetDefault(logger)

	tests := []struct {
		Name             string
		Definition       rdp.Definition
		Result           checks.Results
		MessageSubstring string
	}{
		{
			Name: "Valid",
			Definition: rdp.Definition{
				Host:     host,
				Port:     3389,
				Username: username,
				Password: password,
			},
			Result: checks.Results{
				Passed: true,
			},
		},
		{
			Name: "FailedAuth",
			Definition: rdp.Definition{
				Host:     host,
				Port:     3389,
				Username: username,
				Password: "dummy",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "failed to login:",
		},
		{
			Name: "FailureTemplateParse",
			Definition: rdp.Definition{
				Host:     host,
				Port:     3389,
				Username: username,
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
				t.Fatalf("Check does not match expected result: test(%q) got %t", tt.Name, result.Passed)
			}

			if tt.MessageSubstring != "" && !strings.Contains(result.Message, tt.MessageSubstring) {
				t.Fatalf("Expected message substring %q for check(%q), got message %q", tt.MessageSubstring, tt.Name, result.Message)
			}
		})
	}
}

func TestRDPValidate(t *testing.T) {
	tests := []struct {
		Name            string
		Definition      rdp.Definition
		ValidateMessage string
	}{
		{
			Name: "Valid",
			Definition: rdp.Definition{
				Host:     "rdp.neccdl.org",
				Username: "Administrator",
				Password: "password132",
			},
		},
		{
			Name: "MissingHost",
			Definition: rdp.Definition{
				// Host:      "rdp.neccdl.org",
				Username: "Administrator",
				Password: "password132",
			},
			ValidateMessage: "Host needs to be defined",
		},
		{
			Name: "MissingUsername",
			Definition: rdp.Definition{
				Host: "rdp.neccdl.org",
				// Username: "Administrator",
				Password: "password132",
			},
			ValidateMessage: "Username needs to be defined",
		},
		{
			Name: "MissingPassword",
			Definition: rdp.Definition{
				Host:     "rdp.neccdl.org",
				Username: "Administrator",
				// Password: "password132",
			},
			ValidateMessage: "Password needs to be defined",
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
