package git_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/andrew-aiken/checks"
	"github.com/andrew-aiken/checks/git"
)

func TestGit(t *testing.T) {
	staticConfig := checks.StaticConf{}

	tests := []struct {
		Name             string
		Definition       git.Definition
		Result           checks.Results
		MessageSubstring string
	}{
		{
			Name: "Valid",
			Definition: git.Definition{
				Host:             "github.com",
				Path:             "/git-fixtures/basic.git",
				File:             "CHANGELOG",
				Branch:           "master",
				Protocol:         "https",
				Port:             443,
				MatchContent:     true,
				ContentRegex:     "Initial changelog",
				MatchHeadHash:    true,
				HeadHash:         "6ecf0ef2c2dffb796033e5a02219af86ec6584e5",
				MatchContentHash: true,
				ContentHash:      "95e66b4d944eb483b3b805e756b63d28871d50db8caddf4cb5977639fa998490",
			},
			Result: checks.Results{
				Passed: true,
			},
		},
		{
			Name: "FailureTemplateParse",
			Definition: git.Definition{
				Host:     "github.com",
				Path:     "/git-fixtures/basic.git",
				Username: "dummy",
				Password: "{{",
				Branch:   "master",
				Protocol: "https",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "internal error templating definition",
		},
		{
			Name: "FailedClone",
			Definition: git.Definition{
				Host:     "github.com",
				Path:     "github.com/git-fixtures/basic.git",
				Branch:   "master",
				Protocol: "ssh",
				Token:    "foobar",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Failed clone repository: invalid auth method",
		},
		{
			Name: "MissingFile",
			Definition: git.Definition{
				Host:     "github.com",
				Path:     "/git-fixtures/basic.git",
				File:     "DNE.md",
				Branch:   "master",
				Protocol: "https",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Failed to open file: file does not exist",
		},
		{
			Name: "InvalidRegex",
			Definition: git.Definition{
				Host:         "github.com",
				Path:         "/git-fixtures/basic.git",
				File:         "CHANGELOG",
				Branch:       "master",
				Protocol:     "https",
				MatchContent: true,
				ContentRegex: "[a-z",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Error compiling regex string",
		},
		{
			Name: "NotMatchRegex",
			Definition: git.Definition{
				Host:         "github.com",
				Path:         "/git-fixtures/basic.git",
				File:         "CHANGELOG",
				Branch:       "master",
				Protocol:     "https",
				MatchContent: true,
				ContentRegex: "DNE",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "File contents does not match regex",
		},
		{
			Name: "NotMatchHash",
			Definition: git.Definition{
				Host:             "github.com",
				Path:             "/git-fixtures/basic.git",
				File:             "CHANGELOG",
				Branch:           "master",
				Protocol:         "https",
				MatchContentHash: true,
				ContentHash:      "sha-dummy",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "File content does not match hash",
		},
		{
			Name: "NotMatchHeadSha",
			Definition: git.Definition{
				Host:          "github.com",
				Path:          "/git-fixtures/basic.git",
				File:          "CHANGELOG",
				Branch:        "master",
				Protocol:      "https",
				MatchHeadHash: true,
				HeadHash:      "sha-dummy",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Branch head commit does not match",
		},
		{
			Name: "CheckoutTag",
			Definition: git.Definition{
				Host:         "github.com",
				Path:         "/zpqrtbnk/test-repo",
				Tag:          "v7.7.13",
				Protocol:     "https",
				File:         "foo.txt",
				MatchContent: true,
				ContentRegex: `foo[\s\S]*`,
			},
			Result: checks.Results{
				Passed: true,
			},
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

func TestGitValidate(t *testing.T) {
	tests := []struct {
		Name            string
		Definition      git.Definition
		ValidateMessage string
	}{
		{
			Name: "Valid",
			Definition: git.Definition{
				Host:             "git.neccdl.org",
				Path:             "/admin/dummy.git",
				Token:            "dummyToken",
				File:             "README.md",
				MatchContent:     true,
				ContentRegex:     ".*",
				MatchContentHash: true,
				ContentHash:      "dummy-sha",
				Protocol:         "https",
			},
		},
		{
			Name: "MissingHost",
			Definition: git.Definition{
				// Host:  "git.neccdl.org",
				Path:  "/admin/dummy.git",
				Token: "dummyToken",
			},
			ValidateMessage: "Host needs to be defined",
		},
		{
			Name: "MissingPath",
			Definition: git.Definition{
				Host: "git.neccdl.org",
				// Path:  "/admin/dummy.git",
				Token: "dummyToken",
			},
			ValidateMessage: "Path needs to be defined",
		},
		{
			Name: "PasswordAndToken",
			Definition: git.Definition{
				Host:     "git.neccdl.org",
				Path:     "/admin/dummy.git",
				Token:    "dummyToken",
				Password: "dummyPasswd",
			},
			ValidateMessage: "Either token, password, or neither should be set",
		},
		{
			Name: "InvalidProtocol",
			Definition: git.Definition{
				Host:     "git.neccdl.org",
				Path:     "/admin/dummy.git",
				Token:    "dummyToken",
				Protocol: "ftp",
			},
			ValidateMessage: "Invalid protocol option specified",
		},
		{
			Name: "FilelessMatchContent",
			Definition: git.Definition{
				Host:         "git.neccdl.org",
				Path:         "/admin/dummy.git",
				MatchContent: true,
				ContentRegex: ".*",
				// MatchHeadHash: "dummy-sha",
			},
			ValidateMessage: "File must be specified when matching content",
		},
		{
			Name: "InvalidRegex",
			Definition: git.Definition{
				Host:         "git.neccdl.org",
				Path:         "/admin/dummy.git",
				Token:        "dummyToken",
				File:         "README.md",
				ContentRegex: "[a-z",
				MatchContent: true,
			},
			ValidateMessage: "Failed to compile regex",
		},
		{
			Name: "FilelessMatchHash",
			Definition: git.Definition{
				Host:             "git.neccdl.org",
				Path:             "/admin/dummy.git",
				MatchContentHash: true,
				ContentHash:      "dummy-sha",
			},
			ValidateMessage: "Must specify file when matching content hash is set",
		},
		{
			Name: "HashlessMatchHash",
			Definition: git.Definition{
				Host:             "git.neccdl.org",
				Path:             "/admin/dummy.git",
				File:             "README.md",
				MatchContentHash: true,
			},
			ValidateMessage: "Must specify hash when matching content hash is set",
		},
		{
			Name: "BranchAndTag",
			Definition: git.Definition{
				Host:   "git.neccdl.org",
				Path:   "/admin/dummy.git",
				Branch: "main",
				Tag:    "v1.0.0",
			},
			ValidateMessage: "Either branch or tag should be set",
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
