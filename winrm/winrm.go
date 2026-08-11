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
	// "golang.org/x/crypto/ssh"
)

type Definition struct {
	// IP or hostname of the ldap host
	Host string `json:"host" optiontype:"required"`
	// TCP port number to connect to
	Port uint16 `json:"port" default:"5985"`
	// TODO, see if other methods work, might just be only ntlm
	TransportProtocol string `json:"transportProtocol" default:"ntlm"`
	Insecure          bool   `json:"insecure" default:"false"`
	Command           string `json:"command" default:"whoami"`
	// User to login to
	Username string `json:"username" optiontype:"required"`
	// The users password
	Password string `json:"password" optiontype:"required"`
	// // If the connection should be encrypted
	Encrypted bool `json:"encrypted" default:"false"`
	// whether the response body must match a defined regex for the check to pass
	MatchContent bool `json:"matchContent"`
	// regex for the response body to match
	ContentRegex string `json:"contentRegex" default:".*"`

	Hostname string `json:"hostname"`
	Realm    string `json:"realm"`

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
					errChan <- fmt.Errorf("Failed to set NTLM transport protocol: %v", err)
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
			// This tunnels through another host? not connects to the windows directly
			// case "ssh":
			// 	address := fmt.Sprintf("%s:22", definition.Host) // Hardcoded SSH port
			// 	sshClient, err := ssh.Dial("tcp", address, &ssh.ClientConfig{
			// 		User:            definition.Username,
			// 		Auth:            []ssh.AuthMethod{ssh.Password(definition.Password)},
			// 		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // #nosec G106
			// 	})
			// 	if err != nil {
			// 		fmt.Println(err)
			// 		errChan <- fmt.Errorf("Failed to set SSH dialer: %v", err)
			// 		return
			// 	}
			// 	params.Dial = sshClient.Dial
		}

		client, err := winrmClient.NewClientWithParameters(endpoint, definition.Username, definition.Password, params)
		if err != nil {
			errChan <- fmt.Errorf("failed to create client: %v", err)
			return
		}

		output, stderr, _, err := client.RunCmdWithContext(ctx, definition.Command)
		if err != nil {
			errChan <- fmt.Errorf("failed to run command: %v", err)
			return
		}

		if stderr != "" {
			errChan <- fmt.Errorf("command returned error: %s", stderr)
			return
		}

		if definition.MatchContent {
			regex, err := regexp.Compile(definition.ContentRegex)
			if err != nil {
				errChan <- fmt.Errorf("Error compiling regex string: %s", err)
				return
			}
			if !regex.Match([]byte(output)) {
				errChan <- fmt.Errorf("Matching content not found")
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

	return true, ""
}
