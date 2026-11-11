package s3_test

import (
	"bytes"
	"context"
	"crypto/sha3"
	"encoding/hex"
	"net"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/andrew-aiken/checks"
	"github.com/andrew-aiken/checks/s3"

	"github.com/aws/aws-sdk-go-v2/aws"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	s3mock "github.com/grafana/s3-mock"
)

const (
	bucketName = "test"
	objectName = "test.txt"
	region     = "us-east-1"
)

var testObjectContentBytes = []byte(`Hello world`)

func TestS3Validate(t *testing.T) {
	tests := []struct {
		Name            string
		Definition      s3.Definition
		ValidateMessage string
	}{
		{
			Name: "Valid",
			Definition: s3.Definition{
				Host:   "s3.neccdl.org",
				Bucket: bucketName,
			},
		},
		{
			Name: "MissingHost",
			Definition: s3.Definition{
				// Host:   "s3.neccdl.org",
				Bucket: bucketName,
			},
			ValidateMessage: "Host needs to be defined",
		},
		{
			Name: "MissingBucket",
			Definition: s3.Definition{
				Host: "s3.neccdl.org",
				// Bucket: bucketName,
			},
			ValidateMessage: "Bucket needs to be defined",
		},
		{
			Name: "InvalidRegex",
			Definition: s3.Definition{
				Host:         "s3.neccdl.org",
				Bucket:       bucketName,
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

func TestS3Connection(t *testing.T) {
	staticConfig := checks.StaticConf{}

	serverURL := startMockServer(t)
	host, port := splitHostPort(t, serverURL.Host)

	digest := sha3.Sum256(testObjectContentBytes)
	digestString := hex.EncodeToString(digest[:])

	tests := []struct {
		Name             string
		Definition       s3.Definition
		Result           checks.Results
		MessageSubstring string
	}{
		{
			Name: "FailureTemplateParse",
			Definition: s3.Definition{
				Host:   "{{",
				Port:   port,
				Bucket: bucketName,
				Region: region,
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "internal error templating definition",
		},
		{
			Name: "SuccessfulFullCall",
			Definition: s3.Definition{
				Host:             host,
				Port:             port,
				Bucket:           bucketName,
				AccessKey:        "AKID",
				SecretKey:        "SECRET",
				Region:           region,
				Object:           objectName,
				MatchContent:     true,
				ContentRegex:     `Hello.*`,
				MatchContentHash: true,
				Hash:             digestString,
			},
			Result: checks.Results{
				Passed: true,
			},
		},
		{
			Name: "SuccessfulSimple",
			Definition: s3.Definition{
				Host:   host,
				Port:   port,
				Bucket: bucketName,
				Region: region,
			},
			Result: checks.Results{
				Passed: true,
			},
		},
		{
			Name: "ConnectionRefused",
			Definition: s3.Definition{
				Host:   "127.0.0.1",
				Port:   1337,
				Bucket: bucketName,
				Region: region,
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Could not access bucket test",
		},
		{
			Name: "BucketDNE",
			Definition: s3.Definition{
				Host:   host,
				Port:   port,
				Bucket: "dne",
				Region: region,
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Could not access bucket dne",
		},
		{
			Name: "ObjectDNE",
			Definition: s3.Definition{
				Host:   host,
				Port:   port,
				Bucket: bucketName,
				Region: region,
				Object: "dne.txt",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Could not retrieve object dne.txt",
		},
		{
			Name: "InvalidRegex",
			Definition: s3.Definition{
				Host:         host,
				Port:         port,
				Bucket:       bucketName,
				Region:       region,
				Object:       objectName,
				MatchContent: true,
				ContentRegex: "[a-z",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Error compiling regex string",
		},
		{
			Name: "FailedRegexMatch",
			Definition: s3.Definition{
				Host:         host,
				Port:         port,
				Bucket:       bucketName,
				Region:       region,
				Object:       objectName,
				MatchContent: true,
				ContentRegex: `^Goodbye`,
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Object contents does not match regex",
		},
		{
			Name: "IncorrectHash",
			Definition: s3.Definition{
				Host:             host,
				Port:             port,
				Bucket:           bucketName,
				Region:           region,
				Object:           objectName,
				MatchContentHash: true,
				Hash:             "FOO",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Object content does not match hash",
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			ctx := context.Background()
			timeoutContext, cxtCancel := context.WithTimeout(ctx, 3*time.Second)
			defer cxtCancel()

			result := tt.Definition.Run(timeoutContext, staticConfig)

			if result.Passed != tt.Result.Passed {
				t.Fatalf("Check does not match expected result: test(%q) got %t: %s", tt.Name, result.Passed, result.Message)
			}

			if tt.MessageSubstring != "" && !strings.Contains(result.Message, tt.MessageSubstring) {
				t.Fatalf("Expected message substring %q for check(%q), got message %q", tt.MessageSubstring, tt.Name, result.Message)
			}
		})
	}
}

// TestS3TLSConnection verifies the check can connect over HTTPS
func TestS3TLSConnection(t *testing.T) {
	staticConfig := checks.StaticConf{}

	serverURL := startMockServer(t)

	// The mock only serves plain HTTP so front it with a TLS proxy
	tlsServer := httptest.NewTLSServer(httputil.NewSingleHostReverseProxy(serverURL))
	defer tlsServer.Close()

	tlsServerURL, err := url.Parse(tlsServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, port := splitHostPort(t, tlsServerURL.Host)

	tests := []struct {
		Name             string
		Definition       s3.Definition
		Result           checks.Results
		MessageSubstring string
	}{
		{
			Name: "SuccessfulTLSConnection",
			Definition: s3.Definition{
				Host:          host,
				Port:          port,
				Bucket:        bucketName,
				Region:        region,
				Object:        objectName,
				TLS:           true,
				TLSSkipVerify: true,
			},
			Result: checks.Results{
				Passed: true,
			},
		},
		{
			Name: "InvalidCertificate",
			Definition: s3.Definition{
				Host:          host,
				Port:          port,
				Bucket:        bucketName,
				Region:        region,
				TLS:           true,
				TLSSkipVerify: false,
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "certificate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			ctx := context.Background()
			timeoutContext, cxtCancel := context.WithTimeout(ctx, 3*time.Second)
			defer cxtCancel()

			result := tt.Definition.Run(timeoutContext, staticConfig)

			if result.Passed != tt.Result.Passed {
				t.Fatalf("Check does not match expected result: test(%q) got %t: %s", tt.Name, result.Passed, result.Message)
			}

			if tt.MessageSubstring != "" && !strings.Contains(result.Message, tt.MessageSubstring) {
				t.Fatalf("Expected message substring %q for check(%q), got message %q", tt.MessageSubstring, tt.Name, result.Message)
			}
		})
	}
}

// startMockServer starts an in-memory S3 server seeded with the test bucket and object
func startMockServer(t *testing.T) *url.URL {
	t.Helper()

	client, closeFn, err := s3mock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := closeFn(context.Background()); err != nil {
			t.Errorf("Error stopping S3 server: %s", err)
		}
	})

	ctx := context.Background()
	if _, err := client.CreateBucket(ctx, &awss3.CreateBucketInput{Bucket: aws.String(bucketName)}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.PutObject(ctx, &awss3.PutObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectName),
		Body:   bytes.NewReader(testObjectContentBytes),
	}); err != nil {
		t.Fatal(err)
	}

	serverURL, err := url.Parse(*client.Options().BaseEndpoint)
	if err != nil {
		t.Fatal(err)
	}

	return serverURL
}

// splitHostPort splits an address into a host and numeric port
func splitHostPort(t *testing.T, address string) (string, uint16) {
	t.Helper()

	host, portString, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}

	port, err := strconv.ParseUint(portString, 10, 16)
	if err != nil {
		t.Fatal(err)
	}

	return host, uint16(port)
}
