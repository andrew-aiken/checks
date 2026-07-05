package checks_test

import (
	"strings"
	"testing"

	"github.com/andrew-aiken/checks"
)

type Test struct {
	name                string
	input               any
	expected            string
	expectedErrorString string
}

func TestTemplateDefinition(t *testing.T) {
	config := checks.StaticConf{
		TeamNumber:    1,
		TeamNumberHex: "1",
	}

	tests := []Test{
		{
			name:     "non-template",
			input:    `{"foo": "bar"}`,
			expected: `"{\"foo\": \"bar\"}"`,
		},
		{
			name:     "template",
			input:    `{"foo": "{{.TeamNumber}}"}`,
			expected: `"{\"foo\": \"1\"}"`,
		},
		{
			name:                "bad-template",
			input:               `{"foo": "{{.dne}}"}`,
			expectedErrorString: `template: :1:15: executing "" at <.dne>: can't evaluate field dne in type checks.StaticConf`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bytes, err := checks.TemplateDefinition(tt.input, config)

			if err != nil {
				if !strings.HasPrefix(err.Error(), tt.expectedErrorString) {
					t.Fatal(err)
				}
			}
			output := string(bytes)
			if tt.expected != output {
				t.Errorf("Output does not match expected results, expected %s, got: %s", tt.expected, output)
			}
		})
	}
}
