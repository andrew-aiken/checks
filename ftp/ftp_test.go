package ftp_test

import (
	"context"
	"crypto/sha3"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/andrew-aiken/checks"
	"github.com/andrew-aiken/checks/ftp"
	"github.com/spf13/afero"

	ftpserver "github.com/fclairamb/ftpserverlib"
)

func TestFTPValidate(t *testing.T) {
	tests := []struct {
		Name            string
		Definition      ftp.Definition
		ValidateMessage string
	}{
		{
			Name: "Valid",
			Definition: ftp.Definition{
				Host:     "ftp.neccdl.org",
				Port:     21,
				Username: "dummy",
			},
		},
		{
			Name: "MissingHost",
			Definition: ftp.Definition{
				// Host:     "ftp.neccdl.org",
				Port:     21,
				Username: "dummy",
			},
			ValidateMessage: "Host needs to be defined",
		},
		{
			Name: "MissingUsername",
			Definition: ftp.Definition{
				Host: "ftp.neccdl.org",
				Port: 21,
				// Username: "dummy",
			},
			ValidateMessage: "Username needs to be defined",
		},
		{
			Name: "InvalidRegex",
			Definition: ftp.Definition{
				Host:         "ftp.neccdl.org",
				Port:         21,
				Username:     "dummy",
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

func TestFTPConnection(t *testing.T) {
	staticConfig := checks.StaticConf{}

	ftpDir := t.TempDir()
	fileName := "test.txt"
	testFile := ftpDir + "/" + fileName

	var serverPort uint16 = 2121

	username := "dummy"
	password := "dummy"

	testFileContentBytes := []byte(`Hello world`)

	digest := sha3.Sum256(testFileContentBytes)
	digestString := hex.EncodeToString(digest[:])

	if err := os.WriteFile(testFile, testFileContentBytes, 0600); err != nil {
		t.Fatal(err)
	}

	server := ftpserver.NewFtpServer(&testDriver{
		rootDir:  ftpDir,
		username: username,
		password: password,
		settings: &ftpserver.Settings{
			ListenAddr: fmt.Sprintf("127.0.0.1:%d", serverPort),
		},
	})

	go server.ListenAndServe()
	defer server.Stop()

	tests := []struct {
		Name             string
		Definition       ftp.Definition
		Result           checks.Results
		MessageSubstring string
	}{
		{
			Name: "FailureTemplateParse",
			Definition: ftp.Definition{
				Host:     "{{",
				Port:     serverPort,
				Username: username,
				Password: password,
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "internal error templating definition",
		},
		{
			Name: "SuccessfulFullCall",
			Definition: ftp.Definition{
				Host:             "127.0.0.1",
				Port:             serverPort,
				Username:         username,
				Password:         password,
				File:             fileName,
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
			Definition: ftp.Definition{
				Host:     "127.0.0.1",
				Port:     serverPort,
				Username: username,
				Password: password,
			},
			Result: checks.Results{
				Passed: true,
			},
		},
		{
			Name: "ConnectionTimeout",
			Definition: ftp.Definition{
				Host:     "127.0.0.1",
				Port:     1337,
				Username: username,
				Password: password,
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Connection to 127.0.0.1 on port 1337 failed",
		},
		{
			Name: "FailedLogin",
			Definition: ftp.Definition{
				Host:     "127.0.0.1",
				Port:     serverPort,
				Username: "dne",
				Password: password,
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Login attempt with user dne failed",
		},
		{
			Name: "FileDNE",
			Definition: ftp.Definition{
				Host:     "127.0.0.1",
				Port:     serverPort,
				Username: username,
				Password: password,
				File:     "dne.txt",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Could not retrieve file dne.txt",
		},
		{
			Name: "InvalidRegex",
			Definition: ftp.Definition{
				Host:         "127.0.0.1",
				Port:         serverPort,
				Username:     username,
				Password:     password,
				File:         fileName,
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
			Definition: ftp.Definition{
				Host:         "127.0.0.1",
				Port:         serverPort,
				Username:     username,
				Password:     password,
				File:         fileName,
				MatchContent: true,
				ContentRegex: "DNE",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "File contents does not match regex",
		},
		{
			Name: "IncorrectHash",
			Definition: ftp.Definition{
				Host:             "127.0.0.1",
				Port:             serverPort,
				Username:         username,
				Password:         password,
				File:             fileName,
				MatchContentHash: true,
				Hash:             "FOO",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "File content does not match hash",
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			ctx := context.Background()
			timeoutContext, cxtCancel := context.WithTimeout(ctx, 3*time.Second)
			defer cxtCancel()

			result := tt.Definition.Run(timeoutContext, staticConfig)

			if result.Passed != tt.Result.Passed {
				t.Fatalf("Check result does not match expected result(%q) message %t", tt.Name, result.Passed)
			}

			if tt.MessageSubstring != "" && !strings.Contains(result.Message, tt.MessageSubstring) {
				t.Fatalf("Expected message substring %q for check(%q), got message %q", tt.MessageSubstring, tt.Name, result.Message)
			}
		})
	}
}

// Connect to an FTP server without a password
func TestAnonymousFTP(t *testing.T) {
	staticConfig := checks.StaticConf{}

	var serverPort uint16 = 2122

	username := "Anonymous"

	server := ftpserver.NewFtpServer(&testDriver{
		rootDir:  t.TempDir(),
		username: username,
		settings: &ftpserver.Settings{
			ListenAddr: fmt.Sprintf("127.0.0.1:%d", serverPort),
		},
	})

	go server.ListenAndServe()
	defer server.Stop()

	definition :=ftp.Definition{
			Host:     "127.0.0.1",
			Port:     serverPort,
			Username: username,
			Password: "",
	}

	ctx := context.Background()
	timeoutContext, cxtCancel := context.WithTimeout(ctx, 3*time.Second)
	defer cxtCancel()

	result := definition.Run(timeoutContext, staticConfig)

	fmt.Println(result.Passed)
	fmt.Println(result.Message)

	if !result.Passed {
		t.Fatal("Check failed to connect")
	}
}

// Wrapper around ftpserverlib interfaces
type testDriver struct {
	settings *ftpserver.Settings
	rootDir  string
	username string
	password string
}

func (d *testDriver) GetSettings() (*ftpserver.Settings, error) {
	return d.settings, nil
}

func (d *testDriver) ClientConnected(cc ftpserver.ClientContext) (string, error) {
	return "Welcome to the test FTP server", nil
}

func (d *testDriver) ClientDisconnected(cc ftpserver.ClientContext) {}

func (d *testDriver) AuthUser(cc ftpserver.ClientContext, user, pass string) (ftpserver.ClientDriver, error) {
	if user != d.username || pass != d.password {
		return nil, fmt.Errorf("invalid username or password")
	}
	// BasePathFs jails the client to rootDir - no path traversal outside it.
	return afero.NewBasePathFs(afero.NewOsFs(), d.rootDir), nil
}

// No TLS for this test server. Return non-nil *tls.Config here if you need
// to test FTPS (AUTH TLS) instead.
func (d *testDriver) GetTLSConfig() (*tls.Config, error) {
	return nil, nil
}
