package imap_test

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/andrew-aiken/checks"
	"github.com/andrew-aiken/checks/imap"
	goimap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-imap/v2/imapserver/imapmemserver"
)

type literal struct {
	*bytes.Reader
	size int64
}

func (l literal) Size() int64 { return l.size }

func newLiteral(data []byte) literal {
	return literal{bytes.NewReader(data), int64(len(data))}
}

func TestIMAP(t *testing.T) {
	host := "localhost"
	var port uint16 = 1143
	username := "user"
	password := "password"
	inbox := "INBOX"

	backend := imapmemserver.New()
	user := imapmemserver.NewUser(username, password)
	if err := user.Create(inbox, nil); err != nil {
		log.Fatalf("failed to create inbox: %s", err.Error())
	}

	msg := []byte(
		"From: alice@example.com\r\n" +
			"To: alice@example.com\r\n" +
			"Subject: Welcome\r\n" +
			"\r\n" +
			"Hello, this is your first message!\r\n",
	)
	if _, err := user.Append(inbox, newLiteral(msg), &goimap.AppendOptions{}); err != nil {
		log.Fatalf("failed to append message one: %v", err)
	}

	backend.AddUser(user)

	server := imapserver.New(&imapserver.Options{
		NewSession: func(conn *imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return backend.NewSession(), nil, nil
		},
		InsecureAuth: true,
	})
	defer func() {
		if err := server.Close(); err != nil {
			log.Fatalf("Failed to stop server: %s", err.Error())
		}
	}()

	addr := fmt.Sprintf("%s:%d", host, port)
	log.Printf("IMAP server up: %s", addr)

	go func() {
		if err := server.ListenAndServe(addr); err != nil {
			log.Fatalf("serve: %v", err)
		}
	}()

	time.Sleep(1 * time.Second)

	staticConfig := checks.StaticConf{}

	tests := []struct {
		Name             string
		Definition       imap.Definition
		Result           checks.Results
		MessageSubstring string
	}{
		{
			Name: "ValidFull",
			Definition: imap.Definition{
				Host:     host,
				Port:     port,
				Username: username,
				Password: password,
				Inbox:    inbox,
			},
			Result: checks.Results{
				Passed: true,
			},
		},
		{
			Name: "ValidFull",
			Definition: imap.Definition{
				Host:           host,
				Port:           port,
				Username:       username,
				Password:       password,
				Inbox:          inbox,
				MatchMailCount: 1,
				MailID:         1,
				MatchSubject:   true,
				SubjectRegex:   "Welcome",
				MatchBody:      true,
				BodyRegex:      "Hello, this.*",
			},
			Result: checks.Results{
				Passed: true,
			},
		},
		{
			Name: "InvalidTemplate",
			Definition: imap.Definition{
				Host:     host,
				Port:     port,
				Username: username,
				Password: "{{",
				Inbox:    inbox,
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "internal error templating definition",
		},
		{
			Name: "InvalidConnection",
			Definition: imap.Definition{
				Host:     host,
				Port:     port + 1,
				Username: username,
				Password: password,
				Inbox:    inbox,
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Failed to dial IMAP server: dial tcp [::1]:1144: connect: connection refused",
		},
		{
			Name: "FailedAuth",
			Definition: imap.Definition{
				Host:     host,
				Port:     port,
				Username: username,
				Password: "dummy",
				Inbox:    inbox,
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Failed to login: imap: NO [AUTHENTICATIONFAILED] Authentication failed",
		},
		{
			Name: "MissingInbox",
			Definition: imap.Definition{
				Host:     host,
				Port:     port,
				Username: username,
				Password: password,
				Inbox:    "DNE",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Failed to select inbox DNE: imap: NO [NONEXISTENT] No such mailbox",
		},
		{
			Name: "IncorrectMailCount",
			Definition: imap.Definition{
				Host:           host,
				Port:           port,
				Username:       username,
				Password:       password,
				Inbox:          inbox,
				MatchMailCount: 99,
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Mail count does not match: expected 99, found 1",
		},
		{
			Name: "SubjectInvalidRegex",
			Definition: imap.Definition{
				Host:         host,
				Port:         port,
				Username:     username,
				Password:     password,
				Inbox:        inbox,
				MailID:       1,
				MatchSubject: true,
				SubjectRegex: "[a-z",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Error compiling subject regex string",
		},
		{
			Name: "SubjectMissedRegex",
			Definition: imap.Definition{
				Host:         host,
				Port:         port,
				Username:     username,
				Password:     password,
				Inbox:        inbox,
				MailID:       1,
				MatchSubject: true,
				SubjectRegex: "DNE",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Subject does not match regex",
		},
		{
			Name: "BodyInvalidRegex",
			Definition: imap.Definition{
				Host:      host,
				Port:      port,
				Username:  username,
				Password:  password,
				Inbox:     inbox,
				MailID:    1,
				MatchBody: true,
				BodyRegex: "[a-z",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Error compiling body regex string",
		},
		{
			Name: "BodyMissedRegex",
			Definition: imap.Definition{
				Host:      host,
				Port:      port,
				Username:  username,
				Password:  password,
				Inbox:     inbox,
				MailID:    1,
				MatchBody: true,
				BodyRegex: "DNE",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Body does not match regex",
		},
		{
			Name: "MissingMessage",
			Definition: imap.Definition{
				Host:     host,
				Port:     port,
				Username: username,
				Password: password,
				Inbox:    inbox,
				MailID:   99,
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "FETCH command did not return any message",
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

func TestIMAPValidate(t *testing.T) {
	tests := []struct {
		Name            string
		Definition      imap.Definition
		ValidateMessage string
	}{
		{
			Name: "Valid",
			Definition: imap.Definition{
				Host:     "mail.neccdl.org",
				Username: "user",
				Password: "dummy",
				Inbox:    "INBOX",
				MailID:   1,
			},
		},
		{
			Name: "MissingHost",
			Definition: imap.Definition{
				// Host:      "mail.neccdl.org",
				Username: "user",
				Password: "dummy",
				Inbox:    "INBOX",
				MailID:   1,
			},
			ValidateMessage: "Host needs to be defined",
		},
		{
			Name: "MissingUsername",
			Definition: imap.Definition{
				Host: "mail.neccdl.org",
				// Username:   "user",
				Password: "dummy",
				Inbox:    "INBOX",
				MailID:   1,
			},
			ValidateMessage: "Username needs to be defined",
		},
		{
			Name: "MissingInbox",
			Definition: imap.Definition{
				Host:     "mail.neccdl.org",
				Username: "user",
				Password: "dummy",
				// Inbox: "INBOX",
				MailID: 1,
			},
			ValidateMessage: "Inbox needs to be defined",
		},
		{
			Name: "MissingMailID",
			Definition: imap.Definition{
				Host:         "mail.neccdl.org",
				Username:     "user",
				Password:     "dummy",
				Inbox:        "INBOX",
				MailID:       0, // Set to "false"
				MatchSubject: true,
			},
			ValidateMessage: "Mail ID must be set to use regex match functionality",
		},
		{
			Name: "InvalidSubjectRegex",
			Definition: imap.Definition{
				Host:         "mail.neccdl.org",
				Username:     "user",
				Password:     "dummy",
				Inbox:        "INBOX",
				MailID:       1,
				MatchSubject: true,
				SubjectRegex: "[a-z",
			},
			ValidateMessage: "Failed to compile subject regex",
		},
		{
			Name: "InvalidBodyRegex",
			Definition: imap.Definition{
				Host:      "mail.neccdl.org",
				Username:  "user",
				Password:  "dummy",
				Inbox:     "INBOX",
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
