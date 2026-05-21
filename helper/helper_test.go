package helper

import (
	"fmt"
	"testing"

	"github.com/andrew-aiken/checks/dns"
	"github.com/andrew-aiken/checks/http"
	"github.com/andrew-aiken/checks/icmp"
	"github.com/andrew-aiken/checks/noop"
	"github.com/andrew-aiken/checks/ssh"
)

func TestNewDefinition(t *testing.T) {
	tests := []struct {
		checkType string
		want      any
		wantErr   bool
	}{
		{"dns", &dns.Definition{}, false},
		{"http", &http.Definition{}, false},
		{"icmp", &icmp.Definition{}, false},
		{"noop", &noop.Definition{}, false},
		{"ssh", &ssh.Definition{}, false},
		{"unknown", nil, true},
		{"", nil, true},
	}

	for _, test := range tests {
		t.Run(test.checkType, func(t *testing.T) {
			got, err := NewDefinition(test.checkType)
			if (err != nil) != test.wantErr {
				t.Fatalf("NewDefinition(%q) error = %v, wantErr %v", test.checkType, err, test.wantErr)
			}
			if test.wantErr {
				return
			}
			if got == nil {
				t.Fatalf("NewDefinition(%q) returned nil, want %T", test.checkType, test.want)
			}
			gotType := fmt.Sprintf("%T", got)
			wantType := fmt.Sprintf("%T", test.want)
			if gotType != wantType {
				t.Errorf("NewDefinition(%q) type = %s, want %s", test.checkType, gotType, wantType)
			}
		})
	}
}
