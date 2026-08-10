package smtp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/andrew-aiken/checks"

	sasl "github.com/emersion/go-sasl"
	gosmtp "github.com/emersion/go-smtp"
)

type Definition struct {
	// IP or hostname of the host to send the email to
	Host string `json:"host" optiontype:"required"`
	// TCP port number to connect to
	Port uint16 `json:"port" default:"25"`
	// User that is sending the email
	Username string `json:"username" optiontype:"required"`
	// The users password
	Password  string `json:"password"`
	Sender    string `json:"sender" optiontype:"required"`
	Recipient string `json:"recipient" optiontype:"required"`
	Body      string `json:"body" default:"Hello from Scorestack"`
	Encrypted bool   `json:"encrypted" default:"false"`
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

	auth := sasl.NewPlainClient("", "user@example.com", "password")

	message := strings.NewReader(definition.Body)

	address := fmt.Sprintf("%s:%d", definition.Host, definition.Port)

	err = gosmtp.SendMail(address, auth, definition.Sender, []string{definition.Recipient}, message)
	if err != nil {
		result.Message = fmt.Sprintf("Failed to connect to SMTP server: %s", err)
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
