package winrm

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/andrew-aiken/checks"

	winrmClient "github.com/masterzen/winrm"
)

type Definition struct {
	// IP or hostname of the ldap host
	Host string `json:"host" optiontype:"required"`
	// TCP port number to connect to
	Port uint16 `json:"port" default:"5985"`
	// User being logged into
	Username string `json:"username" optiontype:"required"`
	// The users password
	Password string `json:"password" optiontype:"required"`
	// Command to run against the target host
	Command string `json:"command" default:"whoami"`
	// Method of authentication, currently only ntlm and kerberos are supported
	TransportProtocol string `json:"transportProtocol" default:"ntlm"`
	// If the connection should be encrypted
	Encrypted bool `json:"encrypted" default:"false"`
	// Allow the connection to go over insecure connections
	Insecure bool `json:"insecure" default:"false"`
	// Whether the response body must match a defined regex for the check to pass
	MatchContent bool `json:"matchContent"`
	// Regex for the response body to match
	ContentRegex string `json:"contentRegex" default:".*"`
	// Hostname, used when connecting with kerberos
	Hostname string `json:"hostname"`
	// Realm, used when connecting with kerberos
	Realm string `json:"realm"`
	// Shared configuration across all checks
	checks.SharedDefinition
}

// Run performs a winrm check
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

	errChan := make(chan error, 1)

	go func() {
		defer close(errChan)
		endpoint := winrmClient.NewEndpoint(
			definition.Host,
			int(definition.Port),
			definition.Encrypted,
			definition.Insecure,
			nil,
			nil,
			nil,
			time.Duration(definition.Timeout)*time.Second,
		)

		params := winrmClient.DefaultParameters

		switch definition.TransportProtocol {
		case "ntlm":
			params.TransportDecorator = func() winrmClient.Transporter {
				encryption, err := winrmClient.NewEncryption("ntlm")
				if err != nil {
					errChan <- fmt.Errorf("failed to set NTLM transport protocol: %w", err)
					return nil
				}
				return encryption
			}
		case "kerberos":
			params.TransportDecorator = func() winrmClient.Transporter {
				protocol := "http"
				if definition.Encrypted {
					protocol = "https"
				}
				return &kerberosTransport{
					Username: definition.Username,
					Password: definition.Password,
					Hostname: definition.Hostname,
					Realm:    definition.Realm,
					KDCHost:  definition.Host,
					Port:     int(definition.Port),
					Proto:    protocol,
					SPN:      fmt.Sprintf("%s/%s", strings.ToUpper(protocol), definition.Hostname),
				}
			}
		}

		client, err := winrmClient.NewClientWithParameters(endpoint, definition.Username, definition.Password, params)
		if err != nil {
			errChan <- fmt.Errorf("failed to create client: %w", err)
			return
		}

		output, stderr, _, err := client.RunCmdWithContext(ctx, definition.Command)
		if err != nil {
			errChan <- fmt.Errorf("failed to run command: %w", err)
			return
		}

		if stderr != "" {
			errChan <- fmt.Errorf("command returned error: %v", stderr)
			return
		}

		if definition.MatchContent {
			regex, err := regexp.Compile(definition.ContentRegex)
			if err != nil {
				errChan <- fmt.Errorf("error compiling regex string: %w", err)
				return
			}
			if !regex.Match([]byte(output)) {
				errChan <- fmt.Errorf("matching content not found")
				return
			}
		}
	}()

	select {
	case <-ctx.Done():
		if ctx.Err() != nil {
			result.Message = ctx.Err().Error()
		} else {
			result.Message = "Context closed: could have timed out?"
		}
		return
	case err := <-errChan:
		if err != nil {
			result.Message = err.Error()
			return
		}
	}

	result.Passed = true
	return
}

// Validate checks if the winrm definition is valid
func (d Definition) Validate() (passed bool, message string) {
	if d.Host == "" {
		return false, "Host needs to be defined"
	}

	if d.Username == "" {
		return false, "Username needs to be defined"
	}

	if d.Password == "" {
		return false, "Password needs to be defined"
	}

	allowedTransportProtocol := []string{"", "ntlm", "kerberos"}
	if !slices.Contains(allowedTransportProtocol, d.TransportProtocol) {
		return false, "Invalid transport protocol option"
	}

	if d.TransportProtocol == "kerberos" && (d.Hostname == "" || d.Realm == "") {
		return false, "When running in Kerberos mode hostname & realm must be set"
	}

	if d.MatchContent && d.ContentRegex != "" {
		if _, err := regexp.Compile(d.ContentRegex); err != nil {
			return false, "Failed to compile regex"
		}
	}

	return true, ""
}
