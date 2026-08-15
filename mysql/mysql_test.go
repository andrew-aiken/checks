package mysql_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/andrew-aiken/checks"
	"github.com/andrew-aiken/checks/mysql"
)

// TestMySQL attempts to connect to a local MySQL server to run check tests against
func TestMySQL(t *testing.T) {
	// No simple go libraries for spinning up a local MySQL server
	// This test relies on an external server
	if os.Getenv("CI_MYSQL") == "" {
		t.Skip("CI_MYSQL test flag not set")
	}

	staticConfig := checks.StaticConf{}

	var serverPort uint16 = 3306

	databaseHost := "127.0.0.1"
	username := "root"
	password := "rootPassword"
	database := "test"

	tests := []struct {
		Name             string
		Definition       mysql.Definition
		Result           checks.Results
		MessageSubstring string
	}{
		{
			Name: "Valid",
			Definition: mysql.Definition{
				Host:         databaseHost,
				Port:         serverPort,
				Username:     username,
				Password:     password,
				Database:     database,
				Query:        "SELECT age FROM test.`table` WHERE username like 'johndoe'",
				MatchContent: true,
				ContentRegex: "99",
				TLS:          "skip-verify",
			},
			Result: checks.Results{
				Passed: true,
			},
		},
		{
			Name: "NoQuery",
			Definition: mysql.Definition{
				Host:     databaseHost,
				Port:     serverPort,
				Username: username,
				Password: password,
				Database: database,
				TLS:      "false",
			},
			Result: checks.Results{
				Passed: true,
			},
		},
		{
			Name: "NoMatch",
			Definition: mysql.Definition{
				Host:     databaseHost,
				Port:     serverPort,
				Username: username,
				Password: password,
				Database: database,
				Query:    "SELECT age FROM test.`table` WHERE username like 'johndoe'",
			},
			Result: checks.Results{
				Passed: true,
			},
		},
		{
			Name: "FailureTemplateParse",
			Definition: mysql.Definition{
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
			Definition: mysql.Definition{
				Host:     databaseHost,
				Port:     serverPort + 1,
				Username: username,
				Password: password,
				Database: database,
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Failed to connect to database",
		},
		{
			Name: "FailedQuery",
			Definition: mysql.Definition{
				Host:     databaseHost,
				Port:     serverPort,
				Username: username,
				Password: password,
				Database: database,
				Query:    "SELECT * FROM dne",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Failed to query database: Error 1146",
		},
		{
			Name: "BadRegex",
			Definition: mysql.Definition{
				Host:         databaseHost,
				Port:         serverPort,
				Username:     username,
				Password:     password,
				Database:     database,
				Query:        "SELECT age FROM test.`table` WHERE username like 'johndoe'",
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
			Definition: mysql.Definition{
				Host:         databaseHost,
				Port:         serverPort,
				Username:     username,
				Password:     password,
				Database:     database,
				Query:        "SELECT age FROM test.`table` WHERE username like 'johndoe'",
				MatchContent: true,
				ContentRegex: "DNE",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "File contents does not match regex",
		},
		{
			Name: "NoPassword",
			Definition: mysql.Definition{
				Host:     databaseHost,
				Port:     serverPort,
				Username: "no_password",
				Database: database,
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

func TestMySQLValidate(t *testing.T) {
	tests := []struct {
		Name            string
		Definition      mysql.Definition
		ValidateMessage string
	}{
		{
			Name: "Valid",
			Definition: mysql.Definition{
				Host:     "mysql.neccdl.org",
				Username: "dummy",
				Database: "mysql",
			},
		},
		{
			Name: "MissingHost",
			Definition: mysql.Definition{
				// Host:     "mysql.neccdl.org",
				Username: "dummy",
				Database: "mysql",
			},
			ValidateMessage: "Host needs to be defined",
		},
		{
			Name: "MissingUsername",
			Definition: mysql.Definition{
				Host: "mysql.neccdl.org",
				// Username: "dummy",
				Database: "mysql",
			},
			ValidateMessage: "Username needs to be defined",
		},
		{
			Name: "MissingDatabase",
			Definition: mysql.Definition{
				Host:     "mysql.neccdl.org",
				Username: "dummy",
				// Database: "mysql",
			},
			ValidateMessage: "Database needs to be defined",
		},
		{
			Name: "InvalidTLSOption",
			Definition: mysql.Definition{
				Host:     "mysql.neccdl.org",
				Username: "dummy",
				Database: "mysql",
				TLS:      "dne",
			},
			ValidateMessage: "Invalid TLS option",
		},
		{
			Name: "InvalidRegex",
			Definition: mysql.Definition{
				Host:         "mysql.neccdl.org",
				Username:     "dummy",
				Database:     "mysql",
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
