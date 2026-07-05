package noop_test

import (
	"context"
	"testing"

	"github.com/andrew-aiken/checks"
	"github.com/andrew-aiken/checks/noop"
)

type Test struct {
	Name       string
	Definition noop.Definition
	Result     checks.Results
}

var staticConf = checks.StaticConf{
	TeamNumber:    10,
	TeamNumberHex: "a",
}

func TestNoop(t *testing.T) {
	tests := []Test{
		{
			Name: "Success",
			Definition: noop.Definition{
				Pass: true,
			},
			Result: checks.Results{
				Passed:  true,
				Message: "",
				Details: map[string]string{},
			},
		},
		{
			Name: "Failure",
			Definition: noop.Definition{
				Pass: false,
			},
			Result: checks.Results{
				Passed:  false,
				Message: "",
				Details: map[string]string{},
			},
		},
	}

	var result checks.Results
	ctx := context.Background()

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			pass, message := tt.Definition.Validate()
			if !pass {
				t.Fatalf("Failed to validate check(%q) message %s", tt.Name, message)
			}

			result = tt.Definition.Run(ctx, staticConf)

			if result.Passed != tt.Result.Passed {
				t.Fatalf("Check result does not match expected result(%q) message %t", tt.Name, result.Passed)
			}
		})
	}
}
