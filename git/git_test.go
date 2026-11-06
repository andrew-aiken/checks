package git_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/andrew-aiken/checks"
	"github.com/andrew-aiken/checks/git"

	sshtest "github.com/gliderlabs/ssh"
	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	gossh "golang.org/x/crypto/ssh"
)

func TestGit(t *testing.T) {
	staticConfig := checks.StaticConf{}

	tests := []struct {
		Name             string
		Definition       git.Definition
		Result           checks.Results
		MessageSubstring string
	}{
		{
			Name: "Valid",
			Definition: git.Definition{
				Host:             "github.com",
				Path:             "/git-fixtures/basic.git",
				File:             "CHANGELOG",
				Branch:           "master",
				Protocol:         "https",
				Port:             443,
				MatchContent:     true,
				ContentRegex:     "Initial changelog",
				MatchHeadHash:    true,
				HeadHash:         "6ecf0ef2c2dffb796033e5a02219af86ec6584e5",
				MatchContentHash: true,
				ContentHash:      "95e66b4d944eb483b3b805e756b63d28871d50db8caddf4cb5977639fa998490",
			},
			Result: checks.Results{
				Passed: true,
			},
		},
		{
			Name: "FailureTemplateParse",
			Definition: git.Definition{
				Host:     "github.com",
				Path:     "/git-fixtures/basic.git",
				Username: "dummy",
				Password: "{{",
				Branch:   "master",
				Protocol: "https",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "internal error templating definition",
		},
		{
			Name: "FailedClone",
			Definition: git.Definition{
				Host:     "github.com",
				Path:     "github.com/git-fixtures/basic.git",
				Branch:   "master",
				Protocol: "ssh",
				Token:    "foobar",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Failed clone repository: invalid auth method",
		},
		{
			Name: "MissingFile",
			Definition: git.Definition{
				Host:     "github.com",
				Path:     "/git-fixtures/basic.git",
				File:     "DNE.md",
				Branch:   "master",
				Protocol: "https",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Failed to open file: file does not exist",
		},
		{
			Name: "InvalidRegex",
			Definition: git.Definition{
				Host:         "github.com",
				Path:         "/git-fixtures/basic.git",
				File:         "CHANGELOG",
				Branch:       "master",
				Protocol:     "https",
				MatchContent: true,
				ContentRegex: "[a-z",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Error compiling regex string",
		},
		{
			Name: "NotMatchRegex",
			Definition: git.Definition{
				Host:         "github.com",
				Path:         "/git-fixtures/basic.git",
				File:         "CHANGELOG",
				Branch:       "master",
				Protocol:     "https",
				MatchContent: true,
				ContentRegex: "DNE",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "File contents does not match regex",
		},
		{
			Name: "NotMatchHash",
			Definition: git.Definition{
				Host:             "github.com",
				Path:             "/git-fixtures/basic.git",
				File:             "CHANGELOG",
				Branch:           "master",
				Protocol:         "https",
				MatchContentHash: true,
				ContentHash:      "sha-dummy",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "File content does not match hash",
		},
		{
			Name: "NotMatchHeadSha",
			Definition: git.Definition{
				Host:          "github.com",
				Path:          "/git-fixtures/basic.git",
				File:          "CHANGELOG",
				Branch:        "master",
				Protocol:      "https",
				MatchHeadHash: true,
				HeadHash:      "sha-dummy",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Branch head commit does not match",
		},
		{
			Name: "CheckoutTag",
			Definition: git.Definition{
				Host:         "github.com",
				Path:         "/zpqrtbnk/test-repo",
				Tag:          "v7.7.13",
				Protocol:     "https",
				File:         "foo.txt",
				MatchContent: true,
				ContentRegex: `foo[\s\S]*`,
			},
			Result: checks.Results{
				Passed: true,
			},
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

func TestGitSSHKey(t *testing.T) {
	repoDir := t.TempDir()
	repo, err := gogit.PlainInit(repoDir, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repoDir, "README.md"), []byte("hello over ssh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	worktree, err := repo.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := worktree.Add("README.md"); err != nil {
		t.Fatal(err)
	}
	signature := &object.Signature{Name: "test", Email: "test@example.com", When: time.Now()}
	if _, err := worktree.Commit("initial", &gogit.CommitOptions{Author: signature}); err != nil {
		t.Fatal(err)
	}

	authorizedPublicKey, authorizedPrivateKey := generateKey(t)
	_, unauthorizedPrivateKey := generateKey(t)

	server := &sshtest.Server{
		PublicKeyHandler: func(_ sshtest.Context, key sshtest.PublicKey) bool {
			return sshtest.KeysEqual(key, authorizedPublicKey)
		},
		Handler: func(s sshtest.Session) {
			cmd := exec.CommandContext(s.Context(), "git", "upload-pack", repoDir)
			cmd.Stdin = s
			cmd.Stdout = s
			cmd.Stderr = s.Stderr()
			if err := cmd.Run(); err != nil {
				_ = s.Exit(1)
				return
			}
			_ = s.Exit(0)
		},
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })

	port := uint16(listener.Addr().(*net.TCPAddr).Port)

	tests := []struct {
		Name             string
		Key              string
		Result           checks.Results
		MessageSubstring string
	}{
		{
			Name:   "ValidKey",
			Key:    authorizedPrivateKey,
			Result: checks.Results{Passed: true},
		},
		{
			Name:             "UnauthorizedKey",
			Key:              unauthorizedPrivateKey,
			Result:           checks.Results{Passed: false},
			MessageSubstring: "Failed clone repository",
		},
		{
			Name:             "InvalidKey",
			Key:              "not-a-key",
			Result:           checks.Results{Passed: false},
			MessageSubstring: "Failed to generate clone options: unable to parse private key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			definition := git.Definition{
				Host:         "127.0.0.1",
				Port:         port,
				Protocol:     "ssh",
				Path:         repoDir,
				Branch:       "master",
				Key:          tt.Key,
				File:         "README.md",
				MatchContent: true,
				ContentRegex: "hello over ssh",
			}

			if pass, message := definition.Validate(); !pass {
				t.Fatalf("Failed to validate check(%q) message %s", tt.Name, message)
			}

			timeoutContext, cxtCancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cxtCancel()

			result := definition.Run(timeoutContext, checks.StaticConf{})

			if result.Passed != tt.Result.Passed {
				t.Fatalf("Check does not match expected result: test(%q) got %t message %q", tt.Name, result.Passed, result.Message)
			}

			if tt.MessageSubstring != "" && !strings.Contains(result.Message, tt.MessageSubstring) {
				t.Fatalf("Expected message substring %q for check(%q), got message %q", tt.MessageSubstring, tt.Name, result.Message)
			}
		})
	}
}

func generateKey(t *testing.T) (gossh.PublicKey, string) {
	t.Helper()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	sshPublicKey, err := gossh.NewPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}

	pemBlock, err := gossh.MarshalPrivateKey(privateKey, "")
	if err != nil {
		t.Fatal(err)
	}

	return sshPublicKey, string(pem.EncodeToMemory(pemBlock))
}

func TestGitValidate(t *testing.T) {
	tests := []struct {
		Name            string
		Definition      git.Definition
		ValidateMessage string
	}{
		{
			Name: "Valid",
			Definition: git.Definition{
				Host:             "git.neccdl.org",
				Path:             "/admin/dummy.git",
				Token:            "dummyToken",
				File:             "README.md",
				MatchContent:     true,
				ContentRegex:     ".*",
				MatchContentHash: true,
				ContentHash:      "dummy-sha",
				Protocol:         "https",
			},
		},
		{
			Name: "MissingHost",
			Definition: git.Definition{
				// Host:  "git.neccdl.org",
				Path:  "/admin/dummy.git",
				Token: "dummyToken",
			},
			ValidateMessage: "Host needs to be defined",
		},
		{
			Name: "MissingPath",
			Definition: git.Definition{
				Host: "git.neccdl.org",
				// Path:  "/admin/dummy.git",
				Token: "dummyToken",
			},
			ValidateMessage: "Path needs to be defined",
		},
		{
			Name: "PasswordAndToken",
			Definition: git.Definition{
				Host:     "git.neccdl.org",
				Path:     "/admin/dummy.git",
				Token:    "dummyToken",
				Password: "dummyPasswd",
			},
			ValidateMessage: "Only one of token, password, or key should be set",
		},
		{
			Name: "KeyAndPassword",
			Definition: git.Definition{
				Host:     "git.neccdl.org",
				Path:     "/admin/dummy.git",
				Key:      "dummyKey",
				Password: "dummyPasswd",
				Protocol: "ssh",
			},
			ValidateMessage: "Only one of token, password, or key should be set",
		},
		{
			Name: "KeyWithoutSSH",
			Definition: git.Definition{
				Host:     "git.neccdl.org",
				Path:     "/admin/dummy.git",
				Key:      "dummyKey",
				Protocol: "https",
			},
			ValidateMessage: "Key authentication requires the ssh protocol",
		},
		{
			Name: "InvalidProtocol",
			Definition: git.Definition{
				Host:     "git.neccdl.org",
				Path:     "/admin/dummy.git",
				Token:    "dummyToken",
				Protocol: "ftp",
			},
			ValidateMessage: "Invalid protocol option specified",
		},
		{
			Name: "FilelessMatchContent",
			Definition: git.Definition{
				Host:         "git.neccdl.org",
				Path:         "/admin/dummy.git",
				MatchContent: true,
				ContentRegex: ".*",
				// MatchHeadHash: "dummy-sha",
			},
			ValidateMessage: "File must be specified when matching content",
		},
		{
			Name: "InvalidRegex",
			Definition: git.Definition{
				Host:         "git.neccdl.org",
				Path:         "/admin/dummy.git",
				Token:        "dummyToken",
				File:         "README.md",
				ContentRegex: "[a-z",
				MatchContent: true,
			},
			ValidateMessage: "Failed to compile regex",
		},
		{
			Name: "FilelessMatchHash",
			Definition: git.Definition{
				Host:             "git.neccdl.org",
				Path:             "/admin/dummy.git",
				MatchContentHash: true,
				ContentHash:      "dummy-sha",
			},
			ValidateMessage: "Must specify file when matching content hash is set",
		},
		{
			Name: "HashlessMatchHash",
			Definition: git.Definition{
				Host:             "git.neccdl.org",
				Path:             "/admin/dummy.git",
				File:             "README.md",
				MatchContentHash: true,
			},
			ValidateMessage: "Must specify hash when matching content hash is set",
		},
		{
			Name: "BranchAndTag",
			Definition: git.Definition{
				Host:   "git.neccdl.org",
				Path:   "/admin/dummy.git",
				Branch: "main",
				Tag:    "v1.0.0",
			},
			ValidateMessage: "Either branch or tag should be set",
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
