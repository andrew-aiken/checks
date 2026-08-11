package postgresql_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/andrew-aiken/checks"
	"github.com/andrew-aiken/checks/postgresql"
)

// TestPostgresql attempts to connect to a local postgresql server to run check tests against
func TestPostgresql(t *testing.T) {
	// No simple go libraries for spinning up a local postgresql server
	// This test relies on an external server
	if os.Getenv("CI_POSTGRESQL") == "" {
		t.Skip("CI_POSTGRESQL test flag not set")
	}

	staticConfig := checks.StaticConf{}

	var serverPort uint16 = 5432

	databaseHost := "127.0.0.1"
	username := "postgres"
	password := "rootPassword"
	database := "postgres"

	tests := []struct {
		Name             string
		Definition       postgresql.Definition
		Result           checks.Results
		MessageSubstring string
	}{
		{
			Name: "Valid",
			Definition: postgresql.Definition{
				Host:         databaseHost,
				Port:         serverPort,
				Username:     username,
				Password:     password,
				Database:     database,
				Query:        "SELECT age FROM test.table WHERE username like 'johndoe'",
				MatchContent: true,
				ContentRegex: "99",
				TLS:          "prefer",
			},
			Result: checks.Results{
				Passed: true,
			},
		},
		{
			Name: "NoQuery",
			Definition: postgresql.Definition{
				Host:     databaseHost,
				Port:     serverPort,
				Username: username,
				Password: password,
				Database: database,
				TLS:      "disable",
			},
			Result: checks.Results{
				Passed: true,
			},
		},
		{
			Name: "NoMatch",
			Definition: postgresql.Definition{
				Host:     databaseHost,
				Port:     serverPort,
				Username: username,
				Password: password,
				Database: database,
				Query:    "SELECT age FROM test.table WHERE username like 'johndoe'",
			},
			Result: checks.Results{
				Passed: true,
			},
		},
		{
			Name: "FailureTemplateParse",
			Definition: postgresql.Definition{
				Host:     "{{",
				Port:     serverPort,
				Username: username,
				Password: password,
				Database: database,
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "internal error templating definition",
		},
		{
			Name: "FailConnection",
			Definition: postgresql.Definition{
				Host:     databaseHost,
				Port:     serverPort + 1,
				Username: username,
				Password: password,
				Database: database,
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Failed to setup database connection: failed to connect",
		},
		{
			Name: "FailedQuery",
			Definition: postgresql.Definition{
				Host:     databaseHost,
				Port:     serverPort,
				Username: username,
				Password: password,
				Database: database,
				Query:    "SELECT * FROM test.dne",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: `Failed to query database: ERROR: relation "test.dne" does not exist`,
		},
		{
			Name: "BadRegex",
			Definition: postgresql.Definition{
				Host:         databaseHost,
				Port:         serverPort,
				Username:     username,
				Password:     password,
				Database:     database,
				Query:        "SELECT age FROM test.table WHERE username like 'johndoe'",
				MatchContent: true,
				ContentRegex: "[a-z",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Error compiling regex string: error parsing regexp",
		},
		{
			Name: "NoMatch",
			Definition: postgresql.Definition{
				Host:         databaseHost,
				Port:         serverPort,
				Username:     username,
				Password:     password,
				Database:     database,
				Query:        "SELECT age FROM test.table WHERE username like 'johndoe'",
				MatchContent: true,
				ContentRegex: "DNE",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "File contents does not match regex",
		},
		{
			Name: "InvalidConnectionString",
			Definition: postgresql.Definition{
				Host:     databaseHost,
				Port:     serverPort,
				Username: username,
				Password: password,
				Database: database,
				TLS:      "?",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Failed to parse database connection string",
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			ctx := context.Background()
			timeoutContext, cxtCancel := context.WithTimeout(ctx, 3*time.Second)
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

func TestPostgresqlValidate(t *testing.T) {
	tests := []struct {
		Name            string
		Definition      postgresql.Definition
		ValidateMessage string
	}{
		{
			Name: "Valid",
			Definition: postgresql.Definition{
				Host:     "postgresql.neccdl.org",
				Username: "dummy",
				Database: "postgresql",
			},
		},
		{
			Name: "MissingHost",
			Definition: postgresql.Definition{
				// Host:     "postgresql.neccdl.org",
				Username: "dummy",
				Database: "postgresql",
			},
			ValidateMessage: "Host needs to be defined",
		},
		{
			Name: "MissingUsername",
			Definition: postgresql.Definition{
				Host: "postgresql.neccdl.org",
				// Username: "dummy",
				Database: "postgresql",
			},
			ValidateMessage: "Username needs to be defined",
		},
		{
			Name: "MissingDatabase",
			Definition: postgresql.Definition{
				Host:     "postgresql.neccdl.org",
				Username: "dummy",
				// Database: "postgresql",
			},
			ValidateMessage: "Database needs to be defined",
		},
		{
			Name: "InvalidTLSOption",
			Definition: postgresql.Definition{
				Host:     "postgresql.neccdl.org",
				Username: "dummy",
				Database: "postgresql",
				TLS:      "dne",
			},
			ValidateMessage: "Invalid TLS option",
		},
		{
			Name: "InvalidRegex",
			Definition: postgresql.Definition{
				Host:         "postgresql.neccdl.org",
				Username:     "dummy",
				Database:     "postgresql",
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
