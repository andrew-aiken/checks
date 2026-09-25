package redis_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/andrew-aiken/checks"
	"github.com/andrew-aiken/checks/redis"

	"github.com/alicebob/miniredis/v2"
)

func TestRedisValidation(t *testing.T) {
	tests := []struct {
		Name            string
		Definition      redis.Definition
		ValidateMessage string
	}{
		{
			Name: "Valid",
			Definition: redis.Definition{
				Host: "redis.neccdl.org",
				Port: 6379,
			},
		},
		{
			Name: "MissingHost",
			Definition: redis.Definition{
				// Host:     "redis.neccdl.org",
				Port: 6379,
			},
			ValidateMessage: "Host needs to be defined",
		},
		{
			Name: "InvalidCommand",
			Definition: redis.Definition{
				Host:    "redis.neccdl.org",
				Port:    6379,
				Command: "FOO",
			},
			ValidateMessage: "Invalid command option",
		},
		{
			Name: "MissingKey",
			Definition: redis.Definition{
				Host:    "redis.neccdl.org",
				Port:    6379,
				Command: "GET",
				// Key: "FOO",
			},
			ValidateMessage: "Key must be defined",
		},
		{
			Name: "MissingValue",
			Definition: redis.Definition{
				Host:    "redis.neccdl.org",
				Port:    6379,
				Command: "SET",
				Key:     "FOO",
				// Value: "BAR",
			},
			ValidateMessage: "Value must be defined when using the 'SET' command",
		},
		{
			Name: "InvalidRegex",
			Definition: redis.Definition{
				Host:         "redis.neccdl.org",
				Port:         6379,
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

func TestRedisRun(t *testing.T) {
	staticConfig := checks.StaticConf{}

	s := miniredis.RunT(t)

	err := s.Set("foo", "bar")
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Incr("int", 1)
	if err != nil {
		t.Fatal(err)
	}

	host := s.Host()
	port := s.Server().Addr().AddrPort().Port()

	tests := []struct {
		Name             string
		Definition       redis.Definition
		Result           checks.Results
		MessageSubstring string
	}{
		{
			Name: "Valid",
			Definition: redis.Definition{
				Host:         host,
				Port:         port,
				Command:      "GET",
				Key:          "foo",
				MatchContent: true,
				ContentRegex: "bar",
			},
			Result: checks.Results{
				Passed: true,
			},
		},
		{
			Name: "FailureTemplateParse",
			Definition: redis.Definition{
				Host: "{{",
				Port: port,
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "internal error templating definition",
		},
		{
			Name: "BadConnection",
			Definition: redis.Definition{
				Host: host,
				Port: port + 1,
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: fmt.Sprintf("Error while pinging querying: dial tcp %s:%d: connect: connection refused", host, port+1),
		},
		{
			Name: "MissingGetKey",
			Definition: redis.Definition{
				Host:    host,
				Port:    port,
				Command: "GET",
				Key:     "DNE",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Error key does not exist: redis: nil",
		},
		{
			Name: "Set",
			Definition: redis.Definition{
				Host:    host,
				Port:    port,
				Command: "SET",
				Key:     "key",
				Value:   "1",
			},
			Result: checks.Results{
				Passed: true,
			},
		},
		{
			Name: "Increment",
			Definition: redis.Definition{
				Host:    host,
				Port:    port,
				Command: "INCR",
				Key:     "int",
			},
			Result: checks.Results{
				Passed: true,
			},
		},
		{
			Name: "IncrementString",
			Definition: redis.Definition{
				Host:    host,
				Port:    port,
				Command: "INCR",
				Key:     "foo",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Error while incrementing key: ERR value is not an integer or out of range",
		},
		{
			Name: "BadRegex",
			Definition: redis.Definition{
				Host:         host,
				Port:         port,
				Command:      "GET",
				Key:          "int",
				MatchContent: true,
				ContentRegex: "[a-z",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Error compiling regex string: error parsing regexp",
		},
		{
			Name: "MissedRegex",
			Definition: redis.Definition{
				Host:         host,
				Port:         port,
				Command:      "GET",
				Key:          "int",
				MatchContent: true,
				ContentRegex: "DNE",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Value does not match regex",
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

// TestRedisTLSRun tests TLS & Authentication
func TestRedisTLSRun(t *testing.T) {
	staticConfig := checks.StaticConf{}

	s := miniredis.NewMiniRedis()
	t.Cleanup(s.Close)

	cert := generateSelfSignedCert(t)

	err := s.StartTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
	})
	if err != nil {
		t.Fatal(err.Error())
	}

	username := "user"
	password := "password"
	s.RequireUserAuth(username, password)

	err = s.Set("foo", "bar")
	if err != nil {
		t.Fatal(err)
	}

	host := s.Host()
	port := s.Server().Addr().AddrPort().Port()

	tests := []struct {
		Name             string
		Definition       redis.Definition
		Result           checks.Results
		MessageSubstring string
	}{
		{
			Name: "Valid",
			Definition: redis.Definition{
				Host:          host,
				Port:          port,
				Username:      username,
				Password:      password,
				TLS:           true,
				TLSSkipVerify: true,
				Command:       "GET",
				Key:           "foo",
				MatchContent:  true,
				ContentRegex:  "bar",
			},
			Result: checks.Results{
				Passed: true,
			},
		},
		{
			Name: "BadAuth",
			Definition: redis.Definition{
				Host:          host,
				Port:          port,
				Username:      username,
				Password:      "wrong",
				TLS:           true,
				TLSSkipVerify: true,
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "WRONGPASS",
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

// generateSelfSignedCert creates an in-memory self-signed certificate for use in TLS tests.
func generateSelfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %s", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %s", err)
	}

	cert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}),
	)
	if err != nil {
		t.Fatalf("failed to load key pair: %s", err)
	}

	return cert
}
