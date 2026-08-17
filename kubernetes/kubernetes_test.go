package kubernetes_test

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/andrew-aiken/checks"
	"github.com/andrew-aiken/checks/kubernetes"
)

var token string = "token123"

func TestKubernetes(t *testing.T) {
	if os.Getenv("CI_KUBERNETES") == "" {
		t.Skip("CI_KUBERNETES test flag not set")
	}

	host := "localhost"

	port64, err := strconv.ParseUint(os.Getenv("CI_KUBERNETES_PORT"), 10, 0)
	if err != nil {
		t.Fatalf("Failed to convert port to uint16: %s", err.Error())
	}
	port := uint16(port64)

	ca := os.Getenv("CI_KUBERNETES_CA")
	cert := os.Getenv("CI_KUBERNETES_CERT")
	key := os.Getenv("CI_KUBERNETES_KEY")

	staticConfig := checks.StaticConf{}

	tests := []struct {
		Name             string
		Definition       kubernetes.Definition
		Result           checks.Results
		MessageSubstring string
	}{
		{
			Name: "ValidToken",
			Definition: kubernetes.Definition{
				Host:              host,
				Port:              port,
				TLSSkipVerify:     true,
				MatchMinorVersion: "36",
				Token:             token,
			},
			Result: checks.Results{
				Passed: true,
			},
		},
		{
			Name: "ValidCert",
			Definition: kubernetes.Definition{
				Host:          host,
				Port:          port,
				TLSSkipVerify: false,
				CABase64:      ca,
				CertBase64:    cert,
				KeyBase64:     key,
			},
			Result: checks.Results{
				Passed: true,
			},
		},
		{
			Name: "BadTemplate",
			Definition: kubernetes.Definition{
				Host:  host,
				Port:  port,
				Token: "{{",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "internal error templating definition",
		},
		{
			Name: "BadCertCA",
			Definition: kubernetes.Definition{
				Host:     host,
				Port:     port,
				CABase64: "NotBase64",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Failed to decode root ca certificate",
		},
		{
			Name: "BadCertCert",
			Definition: kubernetes.Definition{
				Host:      host,
				Port:      port,
				KeyBase64: "NotBase64",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Failed to decode key",
		},
		{
			Name: "BadCertKey",
			Definition: kubernetes.Definition{
				Host:       host,
				Port:       port,
				CertBase64: "NotBase64",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Failed to decode client certificate",
		},
		{
			// Failed connection will also error in the same way
			Name: "FailAuthentication",
			Definition: kubernetes.Definition{
				Host:  host,
				Port:  port,
				Token: "XXX",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Failed to connect to apiserver to retrieve version",
		},
		{
			Name: "FailAuthorization",
			Definition: kubernetes.Definition{
				Host:     host,
				Port:     port,
				Query:    "namespace",
				Token:    token,
				CABase64: ca,
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: `Failed to perform query: namespaces is forbidden: User "user" cannot list resource "namespaces" in API group "" at the cluster scope`,
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

func TestKubernetesValidate(t *testing.T) {
	tests := []struct {
		Name            string
		Definition      kubernetes.Definition
		ValidateMessage string
	}{
		{
			Name: "Valid",
			Definition: kubernetes.Definition{
				Host:          "kube.neccdl.org",
				Port:          6443,
				Query:         "pod",
				TLSSkipVerify: false,
				Token:         "token123",
				CABase64:      "WW91J3ZlIGJlZW4gcmljayByb2xsZWQ=",
			},
		},
		{
			Name: "MissingHost",
			Definition: kubernetes.Definition{
				// Host: "kube.neccdl.org",
				Port: 6443,
			},
			ValidateMessage: "Host needs to be defined",
		},
		{
			Name: "InvalidQuery",
			Definition: kubernetes.Definition{
				Host:  "kube.neccdl.org",
				Port:  6443,
				Query: "dne",
			},
			ValidateMessage: "Invalid query option specified",
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
