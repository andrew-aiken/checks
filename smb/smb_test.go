package smb_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/andrew-aiken/checks"
	"github.com/andrew-aiken/checks/smb"
)

func TestSMB(t *testing.T) {
	if os.Getenv("CI_SMB") == "" {
		t.Skip("CI_SMB server test flag not set")
	}

	staticConfig := checks.StaticConf{}

	host := "localhost"
	var port uint16 = 445
	username := "samba"
	password := "secret"
	share := "Data"
	domain := "Data"
	file := "data.txt"

	tests := []struct {
		Name             string
		Definition       smb.Definition
		Result           checks.Results
		MessageSubstring string
	}{
		{
			Name: "Valid",
			Definition: smb.Definition{
				Host:             host,
				Username:         username,
				Port:             port,
				Password:         password,
				Share:            share,
				Domain:           domain,
				File:             file,
				MatchContent:     true,
				ContentRegex:     "Hello World",
				MatchContentHash: true,
				Hash:             "e167f68d6563d75bb25f3aa49c29ef612d41352dc00606de7cbd630bb2665f51",
			},
			Result: checks.Results{
				Passed: true,
			},
		},
		{
			Name: "FailureTemplateParse",
			Definition: smb.Definition{
				Host:     host,
				Username: username,
				Port:     port,
				Password: "{{",
				Share:    share,
				Domain:   domain,
				File:     file,
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "internal error templating definition",
		},
		{
			Name: "InvalidPassword",
			Definition: smb.Definition{
				Host:     host,
				Username: username,
				Port:     port,
				Password: "test",
				Share:    share,
				Domain:   domain,
				File:     file,
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Failed to start smb connection: SessionSetup2: Logon failed",
		},
		{
			Name: "MissingShare",
			Definition: smb.Definition{
				Host:     host,
				Username: username,
				Port:     port,
				Password: password,
				Share:    "DNE",
				Domain:   domain,
				File:     file,
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Failed to tree connect: TreeConnect: Bad network name",
		},
		{
			Name: "MissingFile",
			Definition: smb.Definition{
				Host:     host,
				Username: username,
				Port:     port,
				Password: password,
				Share:    share,
				Domain:   domain,
				File:     "dne.txt",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Failed to read file: Create (read file): Requested file does not exist",
		},
		{
			Name: "InvalidRegex",
			Definition: smb.Definition{
				Host:         host,
				Username:     username,
				Port:         port,
				Password:     password,
				Share:        share,
				Domain:       domain,
				File:         file,
				MatchContent: true,
				ContentRegex: "[a-z",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Error compiling regex string: error parsing regexp",
		},
		{
			Name: "FailedRegexMatch",
			Definition: smb.Definition{
				Host:         host,
				Username:     username,
				Port:         port,
				Password:     password,
				Share:        share,
				Domain:       domain,
				File:         file,
				MatchContent: true,
				ContentRegex: "DNE",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "File contents does not match regex",
		},
		{
			Name: "FailedHashMatch",
			Definition: smb.Definition{
				Host:             host,
				Username:         username,
				Port:             port,
				Password:         password,
				Share:            share,
				Domain:           domain,
				File:             file,
				MatchContentHash: true,
				Hash:             "WrongHash",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "File content does not match expected hash",
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			ctx := context.Background()
			timeoutContext, cxtCancel := context.WithTimeout(ctx, 5*time.Second)
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
