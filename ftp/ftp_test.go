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

	time.Sleep(500 * time.Millisecond)

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

	var serverPort uint16 = 2121

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

	time.Sleep(500 * time.Millisecond)

	definition := ftp.Definition{
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

// TestFTPSConnection verifies the check can connect over explicit TLS (AUTH TLS)
// and that a plaintext connection is rejected when TLS is mandatory
func TestFTPSConnection(t *testing.T) {
	staticConfig := checks.StaticConf{}

	var serverPort uint16 = 2121

	username := "dummy"
	password := "dummy"

	settings := &ftpserver.Settings{
		ListenAddr:  fmt.Sprintf("127.0.0.1:%d", serverPort),
		TLSRequired: ftpserver.MandatoryEncryption,
	}

	server := ftpserver.NewFtpServer(&testDriver{
		rootDir:  t.TempDir(),
		username: username,
		password: password,
		settings: settings,
		tls:      true,
	})

	go server.ListenAndServe()
	defer server.Stop()

	time.Sleep(500 * time.Millisecond)

	tests := []struct {
		Name             string
		Definition       ftp.Definition
		Result           checks.Results
		MessageSubstring string
	}{
		{
			Name: "SuccessfulTLSConnection",
			Definition: ftp.Definition{
				Host:          "127.0.0.1",
				Port:          serverPort,
				Username:      username,
				Password:      password,
				TLS:           true,
				TLSSkipVerify: true,
			},
			Result: checks.Results{
				Passed: true,
			},
		},
		{
			Name: "InvalidCertificate",
			Definition: ftp.Definition{
				Host:          "127.0.0.1",
				Port:          serverPort,
				Username:      username,
				Password:      password,
				TLS:           true,
				TLSSkipVerify: false,
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Login attempt with user dummy failed: tls: failed to verify certificate: x509: certificate signed by unknown authority",
		},
		{
			Name: "LoginWithoutTLS",
			Definition: ftp.Definition{
				Host:     "127.0.0.1",
				Port:     serverPort,
				Username: username,
				Password: password,
				TLS:      false,
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Login attempt with user dummy failed: TLS is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			ctx := context.Background()
			timeoutContext, cxtCancel := context.WithTimeout(ctx, 3*time.Second)
			defer cxtCancel()

			result := tt.Definition.Run(timeoutContext, staticConfig)

			if result.Passed != tt.Result.Passed {
				t.Fatalf("Check result does not match expected result(%q): got %t want %t, message %q", tt.Name, result.Passed, tt.Result.Passed, result.Message)
			}

			if tt.MessageSubstring != "" && !strings.Contains(result.Message, tt.MessageSubstring) {
				t.Fatalf("Expected message substring %q for check(%q), got message %q", tt.MessageSubstring, tt.Name, result.Message)
			}
		})
	}
}

// Wrapper around ftpserverlib interfaces
type testDriver struct {
	settings *ftpserver.Settings
	rootDir  string
	username string
	password string
	tls      bool
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

// GetTLSConfig returns a TLS config using a fixed self-signed test certificate
// when TLS support is enabled for this driver, allowing FTPS (AUTH TLS) tests
func (d *testDriver) GetTLSConfig() (*tls.Config, error) {
	if !d.tls {
		return nil, nil
	}

	keypair, err := tls.X509KeyPair([]byte(localhostCert), []byte(strings.ReplaceAll(localhostKey, "TESTING KEY", "PRIVATE KEY")))
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{keypair},
	}, nil
}

// localhostCert is a self-signed certificate valid for 127.0.0.1, ::1 and example.com,
// This is the well-known Go standard library test certificate (see net/http/internal/testcert).
// https://pkg.go.dev/net/http/internal/testcert
var localhostCert = `-----BEGIN CERTIFICATE-----
MIIDSDCCAjCgAwIBAgIQEP/md970HysdBTpuzDOf0DANBgkqhkiG9w0BAQsFADAS
MRAwDgYDVQQKEwdBY21lIENvMCAXDTcwMDEwMTAwMDAwMFoYDzIwODQwMTI5MTYw
MDAwWjASMRAwDgYDVQQKEwdBY21lIENvMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEAxcl69ROJdxjN+MJZnbFrYxyQooADCsJ6VDkuMyNQIix/Hk15Nk/u
FyBX1Me++aEpGmY3RIY4fUvELqT/srvAHsTXwVVSttMcY8pcAFmXSqo3x4MuUTG/
jCX3Vftj0r3EM5M8ImY1rzA/jqTTLJg00rD+DmuDABcqQvoXw/RV8w1yTRi5BPoH
DFD/AWTt/YgMvk1l2Yq/xI8VbMUIpjBoGXxWsSevQ5i2s1mk9/yZzu0Ysp1tTlzD
qOPa4ysFjBitdXiwfxjxtv5nXqOCP5rheKO0sWLk0fetMp1OV5JSJMAJw6c2ZMkl
U2WMqAEpRjdE/vHfIuNg+yGaRRqI07NZRQIDAQABo4GXMIGUMA4GA1UdDwEB/wQE
AwICpDATBgNVHSUEDDAKBggrBgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MB0GA1Ud
DgQWBBQR5QIzmacmw78ZI1C4MXw7Q0wJ1jA9BgNVHREENjA0ggtleGFtcGxlLmNv
bYINKi5leGFtcGxlLmNvbYcEfwAAAYcQAAAAAAAAAAAAAAAAAAAAATANBgkqhkiG
9w0BAQsFAAOCAQEACrRNgiioUDzxQftd0fwOa6iRRcPampZRDtuaF68yNHoNWbOu
LUwc05eOWxRq3iABGSk2xg+FXM3DDeW4HhAhCFptq7jbVZ+4Jj6HeJG9mYRatAxR
Y/dEpa0D0EHhDxxVg6UzKOXB355n0IetGE/aWvyTV9SiDs6QsaC57Q9qq1/mitx5
2GFBoapol9L5FxCc77bztzK8CpLujkBi25Vk6GAFbl27opLfpyxkM+rX/T6MXCPO
6/YBacNZ7ff1/57Etg4i5mNA6ubCpuc4Gi9oYqCNNohftr2lkJr7REdDR6OW0lsL
rF7r4gUnKeC7mYIH1zypY7laskopiLFAfe96Kg==
-----END CERTIFICATE-----`

// localhostKey is the private key for localhostCert.
var localhostKey = `-----BEGIN RSA TESTING KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDFyXr1E4l3GM34
wlmdsWtjHJCigAMKwnpUOS4zI1AiLH8eTXk2T+4XIFfUx775oSkaZjdEhjh9S8Qu
pP+yu8AexNfBVVK20xxjylwAWZdKqjfHgy5RMb+MJfdV+2PSvcQzkzwiZjWvMD+O
pNMsmDTSsP4Oa4MAFypC+hfD9FXzDXJNGLkE+gcMUP8BZO39iAy+TWXZir/EjxVs
xQimMGgZfFaxJ69DmLazWaT3/JnO7RiynW1OXMOo49rjKwWMGK11eLB/GPG2/mde
o4I/muF4o7SxYuTR960ynU5XklIkwAnDpzZkySVTZYyoASlGN0T+8d8i42D7IZpF
GojTs1lFAgMBAAECggEAIYthUi1lFBDd5gG4Rzlu+BlBIn5JhcqkCqLEBiJIFfOr
/4yuMRrvS3bNzqWt6xJ9MSAC4ZlN/VobRLnxL/QNymoiGYUKCT3Ww8nvPpPzR9OE
sE68TUL9tJw/zZJcRMKwgvrGqSLimfq53MxxkE+kLdOc0v9C8YH8Re26mB5ZcWYa
7YFyZQpKsQYnsmu/05cMbpOQrQWhtmIqRoyn8mG/par2s3NzjtpSE9NINyz26uFc
k/3ovFJQIHkUmTS7KHD3BgY5vuCqP98HramYnOysJ0WoYgvSDNCWw3037s5CCwJT
gCKuM+Ow6liFrj83RrdKBpm5QUGjfNpYP31o+QNP4QKBgQDSrUQ2XdgtAnibAV7u
7kbxOxro0EhIKso0Y/6LbDQgcXgxLqltkmeqZgG8nC3Z793lhlSasz2snhzzooV5
5fTy1y8ikXqjhG0nNkInFyOhsI0auE28CFoDowaQd+5cmCatpN4Grqo5PNRXxm1w
HktfPEgoP11NNCFHvvN5fEKbbQKBgQDwVlOaV20IvW3IPq7cXZyiyabouFF9eTRo
VJka1Uv+JtyvL2P0NKkjYHOdN8gRblWqxQtJoTNk020rVA4UP1heiXALy50gvj/p
hMcybPTLYSPOhAGx838KIcvGR5oskP1aUCmFbFQzGELxhJ9diVVjxUtbG2DuwPKd
tD9TLxT2OQKBgQCcdlHSjp+dzdgERmBa0ludjGfPv9/uuNizUBAbO6D690psPFtY
JQMYaemgSd1DngEOFVWADt4e9M5Lose+YCoqr+UxpxmNlyv5kzJOFcFAs/4XeglB
PHKdgNW/NVKxMc6H54l9LPr+x05sYdGlEtqnP/3W5jhEvhJ5Vjc8YiyVgQKBgQCl
zwjyrGo+42GACy7cPYE5FeIfIDqoVByB9guC5bD98JXEDu/opQQjsgFRcBCJZhOY
M0UsURiB8ROaFu13rpQq9KrmmF0ZH+g8FSzQbzcbsTLg4VXCDXmR5esOKowFPypr
Sm667BfTAGP++D5ya7MLmCv6+RKQ5XD8uEQQAaV2kQKBgAD8qeJuWIXZT0VKkQrn
nIhgtzGERF/6sZdQGW2LxTbUDWG74AfFkkEbeBfwEkCZXY/xmnYqYABhvlSex8jU
supU6Eea21esIxIub2zv/Np0ojUb6rlqTPS4Ox1E27D787EJ3VOXpriSD10vyNnZ
jel6uj2FOP9g54s+GzlSVg/T
-----END RSA TESTING KEY-----`
