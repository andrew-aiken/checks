package aws_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/andrew-aiken/checks"
	"github.com/andrew-aiken/checks/aws"
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

func TestAWSValidate(t *testing.T) {
	tests := []struct {
		Name            string
		Definition      aws.Definition
		ValidateMessage string
	}{
		{
			Name: "Valid",
			Definition: aws.Definition{
				AccessKey:       "ABC123",
				SecretAccesskey: "ABC123",
				Account:         "123456789012",
			},
		},
		{
			Name: "MissingAccessKey",
			Definition: aws.Definition{
				// AccessKey: "ABC123",
				SecretAccesskey: "ABC123",
			},
			ValidateMessage: "Access Key needs to be defined",
		},
		{
			Name: "MissingSecretAccessKey",
			Definition: aws.Definition{
				AccessKey: "ABC123",
				// SecretAccesskey: "ABC123",
			},
			ValidateMessage: "Secret Access Key needs to be defined",
		},
		{
			Name: "IncorrectAccountID",
			Definition: aws.Definition{
				AccessKey:       "ABC123",
				SecretAccesskey: "ABC123",
				Account:         "123",
			},
			ValidateMessage: "Account number must be 12 digits",
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

// newFakeSTS starts a local STS endpoint that answers GetCallerIdentity and verifies the SigV4 signature
func newFakeSTS(t *testing.T, accessKey, secretKey, account string) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if code, err := verifySigV4(r, body, accessKey, secretKey); err != nil {
			w.Header().Set("Content-Type", "text/xml")
			w.WriteHeader(http.StatusForbidden)
			_, fmtErr := fmt.Fprintf(w, `<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><Error><Type>Sender</Type><Code>%s</Code><Message>%s</Message></Error><RequestId>test</RequestId></ErrorResponse>`, code, err)
			if fmtErr != nil {
				w.WriteHeader(http.StatusInternalServerError)
			}
			return
		}

		w.Header().Set("Content-Type", "text/xml")
		_, fmtErr := fmt.Fprintf(w, `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Arn>arn:aws:iam::%[1]s:user/test</Arn><UserId>%[2]s</UserId><Account>%[1]s</Account></GetCallerIdentityResult><ResponseMetadata><RequestId>test</RequestId></ResponseMetadata></GetCallerIdentityResponse>`, account, accessKey)
		if fmtErr != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	t.Cleanup(server.Close)

	return server
}

// verifySigV4 re-signs the request with the expected secret and compares signatures
func verifySigV4(r *http.Request, body []byte, accessKey, secretKey string) (code string, err error) {
	fields := map[string]string{}
	for _, part := range strings.Split(strings.TrimPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 "), ", ") {
		k, v, _ := strings.Cut(part, "=")
		fields[k] = v
	}

	// Credential=AKID/date/region/service/aws4_request
	scope := strings.Split(fields["Credential"], "/")
	if len(scope) != 5 {
		return "IncompleteSignature", fmt.Errorf("malformed credential scope")
	}
	if scope[0] != accessKey {
		return "InvalidClientTokenId", fmt.Errorf("the security token included in the request is invalid")
	}

	signingTime, err := time.Parse("20060102T150405Z", r.Header.Get("X-Amz-Date"))
	if err != nil {
		return "IncompleteSignature", fmt.Errorf("invalid X-Amz-Date: %w", err)
	}

	// Rebuild the request with only the headers the client signed
	req, err := http.NewRequest(r.Method, "http://"+r.Host+r.URL.RequestURI(), bytes.NewReader(body))
	if err != nil {
		return "InternalFailure", err
	}
	for _, h := range strings.Split(fields["SignedHeaders"], ";") {
		if h == "host" || h == "content-length" {
			continue
		}
		req.Header[http.CanonicalHeaderKey(h)] = r.Header.Values(h)
	}

	payloadHash := sha256.Sum256(body)
	creds := awssdk.Credentials{AccessKeyID: accessKey, SecretAccessKey: secretKey}
	err = v4.NewSigner().SignHTTP(context.Background(), creds, req, hex.EncodeToString(payloadHash[:]), scope[3], scope[2], signingTime)
	if err != nil {
		return "InternalFailure", err
	}

	_, expected, _ := strings.Cut(req.Header.Get("Authorization"), "Signature=")
	if !hmac.Equal([]byte(expected), []byte(fields["Signature"])) {
		return "SignatureDoesNotMatch", fmt.Errorf("the request signature we calculated does not match the signature you provided")
	}

	return "", nil
}

func TestAWS(t *testing.T) {
	const (
		accessKey = "AKIAIOSFODNN7EXAMPLE"
		secretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
		account   = "123456789012"
	)

	server := newFakeSTS(t, accessKey, secretKey, account)

	tests := []struct {
		Name             string
		Definition       aws.Definition
		Result           checks.Results
		MessageSubstring string
	}{
		{
			Name: "Valid",
			Definition: aws.Definition{
				AccessKey:       accessKey,
				SecretAccesskey: secretKey,
				Account:         account,
				Endpoint:        server.URL,
			},
			Result: checks.Results{
				Passed: true,
			},
		},
		{
			Name: "FailureTemplateParse",
			Definition: aws.Definition{
				AccessKey:       accessKey,
				SecretAccesskey: secretKey,
				Account:         "{{",
				Endpoint:        server.URL,
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "internal error templating definition",
		},
		{
			Name: "ValidNoAccount",
			Definition: aws.Definition{
				AccessKey:       accessKey,
				SecretAccesskey: secretKey,
				Endpoint:        server.URL,
			},
			Result: checks.Results{
				Passed: true,
			},
		},
		{
			Name: "InvalidAccessKey",
			Definition: aws.Definition{
				AccessKey:       "ABC",
				SecretAccesskey: secretKey,
				Account:         account,
				Endpoint:        server.URL,
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "InvalidClientTokenId",
		},
		{
			Name: "InvalidSecretKey",
			Definition: aws.Definition{
				AccessKey:       accessKey,
				SecretAccesskey: "123",
				Account:         account,
				Endpoint:        server.URL,
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "SignatureDoesNotMatch",
		},
		{
			Name: "WrongAccount",
			Definition: aws.Definition{
				AccessKey:       accessKey,
				SecretAccesskey: secretKey,
				Account:         "210987654321",
				Endpoint:        server.URL,
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "account does not match expected value",
		},
	}

	ctx := context.Background()

	staticConfig := checks.StaticConf{}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			result := tt.Definition.Run(ctx, staticConfig)

			if result.Passed != tt.Result.Passed {
				t.Fatalf("Check does not match expected result: test(%q) got %t: %s", tt.Name, result.Passed, result.Message)
			}

			if tt.MessageSubstring != "" && !strings.Contains(result.Message, tt.MessageSubstring) {
				t.Fatalf("Expected message substring %q for check(%q), got message %q", tt.MessageSubstring, tt.Name, result.Message)
			}
		})
	}
}
