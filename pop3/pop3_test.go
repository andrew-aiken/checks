package pop3_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/andrew-aiken/checks"
	"github.com/andrew-aiken/checks/pop3"
	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
)

func TestPOP3(t *testing.T) {
	if os.Getenv("CI_POP3") == "" {
		t.Skip("CI_POP3 server test flag not set")
	}

	staticConfig := checks.StaticConf{}

	host := "localhost"
	var port uint16 = 1110
	username := "user"
	password := "password"

	if err := sendTestMail(host, "1025", username, password); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		Name             string
		Definition       pop3.Definition
		Result           checks.Results
		MessageSubstring string
	}{
		{
			Name: "InvalidTemplate",
			Definition: pop3.Definition{
				Host:     host,
				Port:     port,
				Username: username,
				Password: "{{",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "internal error templating definition",
		},
		{
			Name: "FailedConnection",
			Definition: pop3.Definition{
				Host:           host,
				Port:           port + 1,
				Username:       username,
				Password:       password,
				Encrypted:      true,
				SkipVerifyCert: true,
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Failed to connect: dial tcp [::1]:1111: connect: connection refused",
		},
		{
			Name: "FailedAuthentication",
			Definition: pop3.Definition{
				Host:           host,
				Port:           port,
				Username:       username,
				Password:       "dummy",
				Encrypted:      true,
				SkipVerifyCert: true,
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Failed to authenticate: invalid password",
		},
		{
			Name: "MismatchMailCount",
			Definition: pop3.Definition{
				Host:           host,
				Port:           port,
				Username:       username,
				Password:       password,
				Encrypted:      true,
				SkipVerifyCert: true,
				MatchMailCount: 99,
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Mail count does not match: expected 99, found 1",
		},
		{
			Name: "SubjectInvalidRegex",
			Definition: pop3.Definition{
				Host:           host,
				Port:           port,
				Username:       username,
				Password:       password,
				Encrypted:      true,
				SkipVerifyCert: true,
				MailID:         1,
				MatchSubject:   true,
				SubjectRegex:   "[a-z",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Error compiling subject regex string",
		},
		{
			Name: "SubjectMissedRegex",
			Definition: pop3.Definition{
				Host:           host,
				Port:           port,
				Username:       username,
				Password:       password,
				Encrypted:      true,
				SkipVerifyCert: true,
				MailID:         1,
				MatchSubject:   true,
				SubjectRegex:   "dne",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Subject does not match regex",
		},
		{
			Name: "BodyInvalidRegex",
			Definition: pop3.Definition{
				Host:           host,
				Port:           port,
				Username:       username,
				Password:       password,
				Encrypted:      true,
				SkipVerifyCert: true,
				MailID:         1,
				MatchBody:      true,
				BodyRegex:      "[a-z",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Error compiling body regex string",
		},
		{
			Name: "BodyMissedRegex",
			Definition: pop3.Definition{
				Host:           host,
				Port:           port,
				Username:       username,
				Password:       password,
				Encrypted:      true,
				SkipVerifyCert: true,
				MailID:         1,
				MatchBody:      true,
				BodyRegex:      "dne",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Body does not match regex",
		},
		{
			Name: "Valid",
			Definition: pop3.Definition{
				Host:           host,
				Port:           port,
				Username:       username,
				Password:       password,
				Encrypted:      true,
				SkipVerifyCert: true,
				MailID:         0,
			},
			Result: checks.Results{
				Passed: true,
			},
		},
		{
			Name: "ValidFull",
			Definition: pop3.Definition{
				Host:           host,
				Port:           port,
				Username:       username,
				Password:       password,
				Encrypted:      true,
				SkipVerifyCert: true,
				MailID:         1,
				MatchSubject:   true,
				SubjectRegex:   "Subject",
				MatchBody:      true,
				BodyRegex:      "foobar",
				MatchMailCount: 1,
				DeleteMail:     true,
			},
			Result: checks.Results{
				Passed: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			ctx := context.Background()
			timeoutContext, cxtCancel := context.WithTimeout(ctx, 5*time.Second)
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

func sendTestMail(host string, port string, username string, password string) error {
	dialer := &net.Dialer{Timeout: 30 * time.Second}

	address := net.JoinHostPort(host, port)
	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		return fmt.Errorf("Failed to connect to SMTP: %w", err)
	}

	tlsConfig := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
	}
	client, err := smtp.NewClientStartTLS(conn, tlsConfig)
	if err != nil {
		return fmt.Errorf("Failed to establish encrypted session: %w", err)
	}

	err = client.Noop()
	if err != nil {
		return fmt.Errorf("Failed to noop ping to server: %w", err)
	}

	auth := sasl.NewPlainClient("", username, password)
	if err = client.Auth(auth); err != nil {
		return fmt.Errorf("Failed to authenticate as: %w", err)
	}

	message := fmt.Sprintf("Subject: %s\n\n%s\n\n", "Subject", "foobar")

	messageReader := strings.NewReader(message)
	if err = client.SendMail("to@example.com", []string{"for@example.com"}, messageReader); err != nil {
		return fmt.Errorf("Failed to send mail: %w", err)
	}

	time.Sleep(500 * time.Millisecond)
	return nil
}

func TestPOP3Validate(t *testing.T) {
	tests := []struct {
		Name            string
		Definition      pop3.Definition
		ValidateMessage string
	}{
		{
			Name: "Valid",
			Definition: pop3.Definition{
				Host:       "mail.neccdl.org",
				Username:   "user",
				Password:   "dummy",
				MailID:     1,
				DeleteMail: true,
			},
		},
		{
			Name: "MissingHost",
			Definition: pop3.Definition{
				// Host:      "mail.neccdl.org",
				Username:   "user",
				Password:   "dummy",
				MailID:     1,
				DeleteMail: true,
			},
			ValidateMessage: "Host needs to be defined",
		},
		{
			Name: "MissingUsername",
			Definition: pop3.Definition{
				Host: "mail.neccdl.org",
				// Username:   "user",
				Password:   "dummy",
				MailID:     1,
				DeleteMail: true,
			},
			ValidateMessage: "Username needs to be defined",
		},
		{
			Name: "MissingMailID",
			Definition: pop3.Definition{
				Host:       "mail.neccdl.org",
				Username:   "user",
				Password:   "dummy",
				MailID:     0, // Set to "false"
				DeleteMail: true,
			},
			ValidateMessage: "Mail id must be set to use match or delete functionality",
		},
		{
			Name: "InvalidSubjectRegex",
			Definition: pop3.Definition{
				Host:         "mail.neccdl.org",
				Username:     "user",
				Password:     "dummy",
				MailID:       1,
				MatchSubject: true,
				SubjectRegex: "[a-z",
			},
			ValidateMessage: "Failed to compile subject regex",
		},
		{
			Name: "InvalidBodyRegex",
			Definition: pop3.Definition{
				Host:      "mail.neccdl.org",
				Username:  "user",
				Password:  "dummy",
				MailID:    1,
				MatchBody: true,
				BodyRegex: "[a-z",
			},
			ValidateMessage: "Failed to compile body regex",
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
