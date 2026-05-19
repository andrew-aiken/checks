package ssh

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"time"

	"github.com/andrew-aiken/checks"

	"golang.org/x/crypto/ssh"
)

type Definition struct {
	Command      string `json:"command" optiontype:"required"`  // Command to run if successfully connected with SSH
	ContentRegex string `json:"contentRegex" default:".*"`      // regex for the response to match
	Host         string `json:"host" optiontype:"required"`     // IP or hostname of the host to run the SSH check against
	KeyFile      string `json:"keyFile"`                        // Path to local SSH key
	Port         uint16  `json:"port" default:"22"`              // SSH port
	Username     string `json:"username" optiontype:"required"` // User to SSH with
	Password     string `json:"password"`                       // User password
	MatchContent bool   `json:"matchContent"`                   // Whether the response must match a defined regex for the check to pass
	Timeout      uint8   `json:"timeout" default:"20"`           // Timeout for the SSH client connection in seconds
}

func (d *Definition) Run(ctx context.Context, static checks.StaticConf) checks.Results {
	result := checks.Results{Timestamp: time.Now()}

	definitionBytes, err := checks.TemplateDefinition(d, static)
	if err != nil {
		result.Message = fmt.Sprintf("internal error templating definition: %s", err)
		return result
	}

	var definition Definition
	err = json.Unmarshal(definitionBytes, &definition)
	if err != nil {
		result.Message = fmt.Sprintf("internal error unmarshaling templated definition: %s", err)
		return result
	}

	sshConfig := &ssh.ClientConfig{
		User:            definition.Username,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         time.Duration(d.Timeout) * time.Second,
	}

	sshConfig.Auth, err = d.generateAuth()
	if err != nil {
		result.Message = fmt.Sprintf("Error when generating ssh auth: %s", err)
		return result
	}

	sshAddress := fmt.Sprintf("%s:%d", definition.Host, definition.Port)

	// Connect with SSh
	sshClient, err := ssh.Dial("tcp", sshAddress, sshConfig)
	if err != nil {
		result.Message = fmt.Sprintf("Failed to connect to %s: %s", sshAddress, err)
		return result
	}
	defer sshClient.Close()

	// Create SSH session
	sshSession, err := sshClient.NewSession()
	if err != nil {
		result.Message = fmt.Sprintf("Failed to create ssh session: %s", err)
		return result
	}
	defer sshSession.Close()

	output, err := sshSession.CombinedOutput(definition.Command)
	if err != nil {
		result.Message = fmt.Sprintf("Error executing command: %s", err)
		return result
	}

	if definition.MatchContent {
		// Match some content
		regex, err := regexp.Compile(d.ContentRegex)
		if err != nil {
			result.Message = fmt.Sprintf("Error compiling regex string %s : %s", d.ContentRegex, err)
			return result
		}

		// Check if the content matches
		if !regex.Match(output) {
			result.Message = "Matching content not found"
			return result
		}
	}

	result.Passed = true

	return result
}

func (d *Definition) generateAuth() ([]ssh.AuthMethod, error) {
	var authMethods []ssh.AuthMethod

	if d.Password != "" {
		authMethods = append(authMethods, ssh.Password(d.Password))
	}

	if d.KeyFile != "" {
		key, err := os.ReadFile(d.KeyFile)
		if err != nil {
			return authMethods, fmt.Errorf("unable to read private key: %v", err)
		}

		// Create the Signer for this private key.
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return authMethods, fmt.Errorf("unable to parse private key: %v", err)
		}

		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}

	return authMethods, nil
}

// Validats the SSH definition is valid
func (d *Definition) Validate() (passed bool, message string) {
	if d.Command == "" {
		return false, "Command needs to be defined"
	}

	if d.Host == "" {
		return false, "Host needs to be defined"
	}

	if d.Username == "" {
		return false, "Username needs to be defined"
	}

	if d.KeyFile == "" && d.Password == "" {
		fmt.Println("Warning | Both ssh keyfile and password are not defined")
	}

	return true, ""
}
