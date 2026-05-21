package helper

import (
	"fmt"

	"github.com/andrew-aiken/checks/dns"
	"github.com/andrew-aiken/checks/http"
	"github.com/andrew-aiken/checks/icmp"
	"github.com/andrew-aiken/checks/noop"
	"github.com/andrew-aiken/checks/ssh"
)

// NewDefinition takes in a check type and returns its definition
func NewDefinition(checkType string) (any, error) {
	switch checkType {
	case "dns":
		return &dns.Definition{}, nil
	case "http":
		return &http.Definition{}, nil
	case "icmp":
		return &icmp.Definition{}, nil
	case "noop":
		return &noop.Definition{}, nil
	case "ssh":
		return &ssh.Definition{}, nil
	default:
		return nil, fmt.Errorf("unknown check type %q", checkType)
	}
}
