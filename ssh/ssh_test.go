package ssh_test

import (
	"bytes"
	"context"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/andrew-aiken/checks"
	"github.com/andrew-aiken/checks/ssh"

	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"

	sshtest "github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
)

type ValidateTest struct {
	Name            string
	Definition      ssh.Definition
	ValidateMessage string
}

type RunTest struct {
	Name             string
	Definition       ssh.Definition
	Result           checks.Results
	MessageSubstring string
	Key              []byte
	KeyPath          string
}

var staticConf = checks.StaticConf{
	TeamNumber:    10,
	TeamNumberHex: "a",
}

func TestSSGValidate(t *testing.T) {
	tests := []ValidateTest{
		{
			Name: "Valid",
			Definition: ssh.Definition{
				Host:     "server",
				Username: "dummy",
				Password: "password123",
				Command:  "whoami",
			},
		},
		{
			Name: "MissingHost",
			Definition: ssh.Definition{
				// Host:     "",
				Username: "dummy",
				Password: "password123",
				Command:  "whoami",
			},
			ValidateMessage: "Host needs to be defined",
		},
		{
			Name: "MissingHost",
			Definition: ssh.Definition{
				// Host:     "",
				Username: "user",
				Password: "password",
				Command:  "whoami",
			},
			ValidateMessage: "Host needs to be defined",
		},
		{
			Name: "MissingUsername",
			Definition: ssh.Definition{
				Host: "server",
				// Username: "",
				Password: "password",
				Command:  "whoami",
			},
			ValidateMessage: "Username needs to be defined",
		},
		{
			Name: "MultiAuth",
			Definition: ssh.Definition{
				Host:     "server",
				Username: "user",
				Command:  "whoami",
			},
			ValidateMessage: "No authentication method defined",
		},
		{
			Name: "KeyAndKeyfile",
			Definition: ssh.Definition{
				Host:     "server",
				Username: "user",
				Command:  "whoami",
				Key:      "ssh-rsa ...",
				KeyFile:  "/foo/bar",
			},
			ValidateMessage: "Cannot have both Key and KeyFile defined",
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

func TestSSHRun(t *testing.T) {
	serverHostName := "localhost"
	serverPassword := "password123"
	var serverPort uint16 = 2222
	serverResponse := "foobar"

	tests := []RunTest{
		{
			Name: "ValidConnection",
			Definition: ssh.Definition{
				Host:     serverHostName,
				Username: "dummy",
				Password: serverPassword,
				Port:     serverPort,
			},
			Result: checks.Results{
				Passed: true,
			},
		},
		{
			Name: "BadPassword",
			Definition: ssh.Definition{
				Host:     serverHostName,
				Username: "dummy",
				Password: "wrong",
				Port:     serverPort,
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Failed to connect to localhost:2222: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password]",
		},
		{
			Name: "ValidConnectionCommand",
			Definition: ssh.Definition{
				Host:     serverHostName,
				Username: "dummy",
				Password: serverPassword,
				Port:     serverPort,
				Command:  "whoami",
			},
			Result: checks.Results{
				Passed: true,
			},
		},
		{
			Name: "MatchContentSuccess",
			Definition: ssh.Definition{
				Host:         serverHostName,
				Username:     "dummy",
				Password:     serverPassword,
				Port:         serverPort,
				Command:      "whoami",
				MatchContent: true,
				ContentRegex: serverResponse,
			},
			Result: checks.Results{
				Passed: true,
			},
		},
		{
			Name: "MatchContentFailure",
			Definition: ssh.Definition{
				Host:         serverHostName,
				Username:     "dummy",
				Password:     serverPassword,
				Port:         serverPort,
				Command:      "whoami",
				MatchContent: true,
				ContentRegex: "dummy",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Matching content not found",
		},
		{
			Name: "MatchContentBadRegex",
			Definition: ssh.Definition{
				Host:         serverHostName,
				Username:     "dummy",
				Password:     serverPassword,
				Port:         serverPort,
				Command:      "whoami",
				MatchContent: true,
				ContentRegex: "[a-z",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Error compiling regex string",
		},
		{
			Name: "InvalidTemplate",
			Definition: ssh.Definition{
				Host:     serverHostName,
				Username: "dummy",
				Password: "{{",
				Command:  "whoami",
				Port:     serverPort,
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "internal error templating definition",
		},
		{
			Name: "InvalidPort",
			Definition: ssh.Definition{
				Host:     serverHostName,
				Username: "dummy",
				Password: serverPassword,
				Port:     serverPort + 1,
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Failed to connect to localhost:2223: dial tcp [::1]:2223: connect: connection refused",
		},
	}

	ctx := context.Background()

	sshServer := TestSSH{}
	sshServer.SetupTestServer(TestConfig{
		Address:         fmt.Sprintf("%s:%d", serverHostName, serverPort),
		Password:        serverPassword,
		CommandResponse: serverResponse,
	})

	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", serverHostName, serverPort))
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		sshServer.Serve(listener)
	}()
	t.Cleanup(func() {
		sshServer.Close()
	})

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			pass, message := tt.Definition.Validate()
			if !pass {
				t.Fatalf("Failed to validate check(%q) message %s", tt.Name, message)
			}

			result := tt.Definition.Run(ctx, staticConf)

			if result.Passed != tt.Result.Passed {
				t.Fatalf("Check result does not match expected result(%q) message %t", tt.Name, result.Passed)
			}

			if tt.MessageSubstring != "" && !strings.Contains(result.Message, tt.MessageSubstring) {
				t.Fatalf("Expected message substring %q for check(%q), got message %q", tt.MessageSubstring, tt.Name, result.Message)
			}
		})
	}
}

func TestSSHKey(t *testing.T) {
	serverHostName := "localhost"
	username := "user"
	password := "password123"
	var serverPort uint16 = 2222

	ctx := context.Background()

	// Sourced some of the key generation code from this gist
	// https://gist.github.com/goliatone/e9c13e5f046e34cef6e150d06f20a34c
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	publicRsaKey, err := gossh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	sshPublicKey := string(gossh.MarshalAuthorizedKey(publicRsaKey))

	rsaPrivateSigner := x509.MarshalPKCS1PrivateKey(privateKey)

	privBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   rsaPrivateSigner,
	}

	sshPrivateKey := pem.EncodeToMemory(&privBlock)

	tests := []RunTest{
		{
			Name: "ValidConnection",
			Definition: ssh.Definition{
				Host:     serverHostName,
				Username: username,
				Key:      string(sshPrivateKey),
				Port:     serverPort,
			},
			Result: checks.Results{
				Passed: true,
			},
		},
		{
			Name: "KeyFile",
			Definition: ssh.Definition{
				Host:     serverHostName,
				Username: username,
				KeyFile:  "key.pem",
				Port:     serverPort,
			},
			Key:     sshPrivateKey,
			KeyPath: "key.pem",
			Result: checks.Results{
				Passed: true,
			},
		},
		{
			Name: "KeyFileAndKey", // Validation does not allow this, but test in place to verify it would work
			Definition: ssh.Definition{
				Host:     serverHostName,
				Username: username,
				Key:      string(sshPrivateKey),
				KeyFile:  "key.pem",
				Port:     serverPort,
			},
			Key:     sshPrivateKey,
			KeyPath: "key.pem",
			Result: checks.Results{
				Passed: true,
			},
		},
		{
			Name: "NonExistentKey",
			Definition: ssh.Definition{
				Host:     serverHostName,
				Username: username,
				KeyFile:  "DNE.pem",
				Port:     serverPort,
			},
			Key:     sshPrivateKey,
			KeyPath: "key.pem",
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Error when generating ssh auth: unable to read private key: open",
		},
		{
			Name: "KeyAndPassword",
			Definition: ssh.Definition{
				Host:     serverHostName,
				Username: username,
				Password: password,
				Key:      string(sshPrivateKey),
				Port:     serverPort,
			},
			Result: checks.Results{
				Passed: true,
			},
		},
		{
			Name: "InvalidKey",
			Definition: ssh.Definition{
				Host:     serverHostName,
				Username: username,
				Key:      "not-a-key",
				Port:     serverPort,
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Error when generating ssh auth: unable to parse private key: ssh: no key found",
		},
	}

	sshServer := TestSSH{}
	sshServer.SetupTestServer(TestConfig{
		Address:         fmt.Sprintf("%s:%d", serverHostName, serverPort),
		Password:        password,
		PublicKey:       sshPublicKey,
		CommandResponse: "handler triggered\n",
	})

	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", serverHostName, serverPort))
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		sshServer.Serve(listener)
	}()
	t.Cleanup(func() {
		sshServer.Close()
	})

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			if tt.KeyPath != "" {
				testPath := t.TempDir()
				keyPath := testPath + "/" + tt.KeyPath
				if err := os.WriteFile(keyPath, tt.Key, 0600); err != nil {
					t.Fatal(err)
				}
				tt.Definition.KeyFile = testPath + "/" + tt.Definition.KeyFile
			}

			result := tt.Definition.Run(ctx, staticConf)

			if result.Passed != tt.Result.Passed {
				t.Fatalf("Check result does not match expected result(%q) message %t", tt.Name, result.Passed)
			}

			if tt.MessageSubstring != "" && !strings.Contains(result.Message, tt.MessageSubstring) {
				t.Fatalf("Expected message substring %q for check(%q), got message %q", tt.MessageSubstring, tt.Name, result.Message)
			}
		})
	}
}

// SSH testing framework based around this blog post
// https://medium.com/@metarsit/ssh-is-fun-till-you-need-to-unit-test-it-in-go-f3b3303974ab
type TestConfig struct {
	Address         string
	Password        string
	CommandResponse string
	PublicKey       string
}

type TestSSH struct {
	server *sshtest.Server
}

// Serve handles incoming connections on the already-bound listener l
func (h *TestSSH) Serve(l net.Listener) error {
	return h.server.Serve(l)
}

// Close returns any error returned from closing the Server's underlying Listener(s).
func (h *TestSSH) Close() error {
	return h.server.Close()
}

// SetReturnString takes in a string and set it as the response from the server
func (h *TestSSH) SetReturnString(str string) {
	h.server.Handler = func(s sshtest.Session) {
		io.WriteString(s, str)
	}
}

func (h *TestSSH) SetupTestServer(config TestConfig) {
	h.server = &sshtest.Server{
		Addr: config.Address,
		PasswordHandler: func(ctx sshtest.Context, password string) bool {
			if config.Password == password {
				return true
			}
			return false
		},
		PublicKeyHandler: func(ctx sshtest.Context, clientPublicKey sshtest.PublicKey) bool {
			serverPublicKey, _, _, _, err := gossh.ParseAuthorizedKey([]byte(config.PublicKey))
			if err != nil {
				fmt.Println(err)
				return false
			}

			// Compare the clients public key against the servers
			if bytes.Equal(clientPublicKey.Marshal(), serverPublicKey.Marshal()) {
				return true
			}

			return false
		},
		Handler: func(s sshtest.Session) {
			io.WriteString(s, config.CommandResponse)
		},
	}
}
