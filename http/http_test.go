package http_test

import (
	"context"
	"strings"
	"testing"

	"github.com/andrew-aiken/checks"
	"github.com/andrew-aiken/checks/http"
)

type ValidateTest struct {
	Name            string
	Definition      http.Definition
	ValidateMessage string
}

type RunTest struct {
	Name             string
	Definition       http.Definition
	Result           checks.Results
	MessageSubstring string
}

var staticConf = checks.StaticConf{
	TeamNumber:    10,
	TeamNumberHex: "a",
}

func TestHTTPValidate(t *testing.T) {
	tests := []ValidateTest{
		{
			Name: "Valid",
			Definition: http.Definition{
				Host:   "neccdl.org",
				Path:   "/",
				HTTPS:  true,
				Port:   443,
				Method: "GET",
				Code:   200,
			},
		},
		{
			Name: "MissingHost",
			Definition: http.Definition{
				// Host:         "",
				Path:   "/",
				HTTPS:  true,
				Port:   443,
				Method: "GET",
				Code:   200,
			},
			ValidateMessage: "Host needs to be defined",
		},
		{
			Name: "RedirectWithPort",
			Definition: http.Definition{
				Host:     "neccdl.org",
				Path:     "/",
				HTTPS:    true,
				Port:     443,
				Method:   "GET",
				Code:     200,
				Redirect: true,
			},
			ValidateMessage: "Port unused due to redirect specified",
		},
		{
			Name: "InvalidRegex",
			Definition: http.Definition{
				Host:         "neccdl.org",
				Path:         "/",
				HTTPS:        true,
				Method:       "GET",
				Code:         200,
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

func TestHTTPRun(t *testing.T) {
	tests := []RunTest{
		{
			Name: "ValidGenericRequest",
			Definition: http.Definition{
				Host:   "neccdl.org",
				Path:   "/",
				HTTPS:  true,
				Port:   443,
				Method: "GET",
				Code:   200,
			},
			Result: checks.Results{
				Passed: true,
			},
		},
		{
			Name: "ValidHeaders",
			Definition: http.Definition{
				Host:   "neccdl.org",
				Path:   "/",
				HTTPS:  true,
				Port:   443,
				Method: "GET",
				Code:   200,
				Headers: map[string]string{
					"Host":       "neccdl.org",
					"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:152.0) Gecko/20100101 Firefox/152.0",
				},
			},
			Result: checks.Results{
				Passed: true,
			},
		},
		{
			Name: "FollowRedirect",
			Definition: http.Definition{
				Host:     "neccdl.org",
				Path:     "/",
				HTTPS:    false,
				Method:   "GET",
				Code:     200,
				Redirect: true,
			},
			Result: checks.Results{
				Passed: true,
			},
		},
		{
			Name: "FailedRequest",
			Definition: http.Definition{
				Host:   "dne.neccdl.org",
				Path:   "/",
				HTTPS:  true,
				Port:   443,
				Method: "GET",
				Code:   200,
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: `Error making request: Get "https://dne.neccdl.org:443/": dial tcp: lookup dne.neccdl.org`,
		},
		{
			Name: "InvalidHost",
			Definition: http.Definition{
				Host:   "^&@/neccdl.org",
				Path:   "/",
				HTTPS:  true,
				Port:   443,
				Method: "GET",
				Code:   200,
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: `Error constructing request: parse "https://^&@/neccdl.org:443/": net/url: invalid userinfo`,
		},
		{
			Name: "MatchStatusCode",
			Definition: http.Definition{
				Host:      "neccdl.org",
				Path:      "/",
				HTTPS:     true,
				Port:      443,
				Method:    "GET",
				Code:      418,
				MatchCode: true,
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Received bad status code: 200",
		},
		{
			Name: "MatchResponseSuccess",
			Definition: http.Definition{
				Host:         "neccdl.org",
				Path:         "/",
				HTTPS:        true,
				Port:         443,
				Method:       "GET",
				Code:         200,
				ContentRegex: "<title>NECCDL</title>",
				MatchContent: true,
			},
			Result: checks.Results{
				Passed: true,
			},
		},
		{
			Name: "MatchResponseFailure",
			Definition: http.Definition{
				Host:         "neccdl.org",
				Path:         "/",
				HTTPS:        true,
				Port:         443,
				Method:       "GET",
				Code:         200,
				ContentRegex: "<title>NOT NECCDL</title>",
				MatchContent: true,
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Received bad response body",
		},
		{
			Name: "InvalidRegex",
			Definition: http.Definition{
				Host:         "neccdl.org",
				Path:         "/",
				HTTPS:        true,
				Port:         443,
				Method:       "GET",
				Code:         200,
				ContentRegex: "[a-z",
				MatchContent: true,
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Error compiling regex string",
		},
	}

	ctx := context.Background()

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
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
