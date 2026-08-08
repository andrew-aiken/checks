package ftp_test

import (
	"context"
	"crypto/sha3"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/andrew-aiken/checks"
	"github.com/andrew-aiken/checks/ftp"
	"github.com/spf13/afero"

	ftpserver "github.com/fclairamb/ftpserverlib"
)

type ValidateTest struct {
	Name            string
	Definition      ftp.Definition
	ValidateMessage string
}

func TestFTPValidate(t *testing.T) {
	tests := []ValidateTest{
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

	testFileContentBytes := []byte(`Hello world
123
`)

	digest := sha3.Sum256(testFileContentBytes)
	digestString := hex.EncodeToString(digest[:])

	if err := os.WriteFile(testFile, testFileContentBytes, 0600); err != nil {
		t.Fatal(err)
	}

	driver := &testDriver{
		rootDir:  ftpDir,
		username: username,
		password: password,
		settings: &ftpserver.Settings{
			ListenAddr: fmt.Sprintf("127.0.0.1:%d", serverPort),
			// PassiveTransferPortRange: &ftpserver.PortRange{
			// 	Start: 21000,
			// 	End:   21010,
			// },
		},
	}

	server := ftpserver.NewFtpServer(driver)

	go server.ListenAndServe()
	defer server.Stop()

	config := ftp.Definition{
		Host:             "127.0.0.1",
		Port:             serverPort,
		Username:         username,
		Password:         password,
		File:             fileName,
		MatchContentHash: true,
		Hash:             digestString,
		MatchContent:     true,
		ContentRegex:     `Hello[\s\S]*`,
	}

	ctx := context.Background()
	timeoutContext, _ := context.WithTimeout(ctx, 5*time.Second)
	results := config.Run(timeoutContext, staticConfig)

	fmt.Println(results.Passed)
	fmt.Println(results.Message)
	for _, detail := range results.Details {
		fmt.Println(detail)
	}

	if !results.Passed {
		t.Fatal(results.Message)
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
