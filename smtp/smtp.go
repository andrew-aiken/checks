package smtp

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/andrew-aiken/checks"

	"github.com/emersion/go-sasl"
	gosmtp "github.com/emersion/go-smtp"
)

type Definition struct {
	// IP or hostname of the host to send the email to
	Host string `json:"host" optiontype:"required"`
	// TCP port number to connect to
	Port uint16 `json:"port" default:"25"`
	// User that is sending the email
	Username string `json:"username"`
	// The users password
	Password string `json:"password"`
	// Sender email address
	Sender string `json:"sender" optiontype:"required"`
	// Recipient email address
	Recipient string `json:"recipient" optiontype:"required"`
	// Subject of the email
	Subject string `json:"subject" default:"Subject"`
	// Body of the email
	Body string `json:"body" default:"Body"`
	// If the connection should be encrypted
	Encrypted bool `json:"encrypted" default:"false"`
	// Whether to verify the server's TLS certificate
	SkipVerifyCert bool `json:"skipVerifyCert" default:"false"`
	// Shared configuration across all checks
	checks.SharedDefinition
}

// Run performs a SMTP check
func (d Definition) Run(ctx context.Context, static checks.StaticConf) (result checks.Results) {
	result = checks.Results{
		Timestamp: time.Now(),
	}

	definitionBytes, err := checks.TemplateDefinition(d, static)
	if err != nil {
		result.Message = fmt.Sprintf("internal error templating definition: %s", err)
		return
	}

	var definition Definition
	err = json.Unmarshal(definitionBytes, &definition)
	if err != nil {
		result.Message = fmt.Sprintf("internal error unmarshaling templated definition: %s", err)
		return
	}

	address := fmt.Sprintf("%s:%d", definition.Host, definition.Port)

	dialer := &net.Dialer{Timeout: time.Duration(definition.Timeout) * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		result.Message = fmt.Sprintf("Failed to connect to SMTP %s: %s", address, err)
		return
	}

	var client *gosmtp.Client
	if definition.Encrypted {
		tlsConfig := &tls.Config{
			ServerName:         definition.Host,
			InsecureSkipVerify: definition.SkipVerifyCert, // #nosec G402
		}
		client, err = gosmtp.NewClientStartTLS(conn, tlsConfig)
		if err != nil {
			result.Message = fmt.Sprintf("Failed to establish encrypted session with %s: %s", address, err)
			return
		}
	} else {
		client = gosmtp.NewClient(conn)
	}
	defer func() {
		clientCloseErr := client.Close()
		if err == nil && clientCloseErr != nil {
			result.Message = fmt.Sprintf("error closing smtp connection: %s", clientCloseErr.Error())
			result.Passed = false
		}
	}()

	err = client.Noop()
	if err != nil {
		result.Message = fmt.Sprintf("Failed to noop ping to server: %s", err)
		return
	}

	if definition.Username != "" {
		auth := sasl.NewPlainClient("", definition.Username, definition.Password)
		if err = client.Auth(auth); err != nil {
			result.Message = fmt.Sprintf("Failed to authenticate as %s: %s", definition.Username, err)
			return
		}
	}

	// https://datatracker.ietf.org/doc/html/rfc822
	message := fmt.Sprintf("Subject: %s\n\n%s\n\n", definition.Subject, definition.Body)

	messageReader := strings.NewReader(message)
	if err = client.SendMail(definition.Sender, []string{definition.Recipient}, messageReader); err != nil {
		result.Message = fmt.Sprintf("Failed to send mail: %s", err)
		return
	}

	result.Passed = true
	return
}

// Validate checks if the smtp definition is valid
func (d Definition) Validate() (passed bool, message string) {
	if d.Host == "" {
		return false, "Host needs to be defined"
	}

	if d.Sender == "" {
		return false, "Sender needs to be defined"
	}

	if d.Recipient == "" {
		return false, "Recipient needs to be defined"
	}

	return true, ""
}
