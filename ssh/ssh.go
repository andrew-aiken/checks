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
	// Command to run if successfully connected with SSH
	Command string `json:"command"`
	// regex for the response to match
	ContentRegex string `json:"contentRegex" default:".*"`
	// IP or hostname of the host to run the SSH check against
	Host string `json:"host" optiontype:"required"`
	// SSH private key
	Key string `json:"key"`
	// Path to local SSH key
	KeyFile string `json:"keyFile"`
	// SSH port
	Port uint16 `json:"port" default:"22"`
	// User to SSH with
	Username string `json:"username" optiontype:"required"`
	// User password
	Password string `json:"password"`
	// Whether the response must match a defined regex for the check to pass
	MatchContent bool `json:"matchContent"`
	// Shared configuration across all checks
	checks.SharedDefinition
}

func (d Definition) Run(ctx context.Context, static checks.StaticConf) (result checks.Results) {
	result = checks.Results{Timestamp: time.Now()}

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

	sshConfig := &ssh.ClientConfig{
		User:            definition.Username,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // #nosec G106
		Timeout:         time.Duration(d.Timeout) * time.Second,
	}

	sshConfig.Auth, err = d.generateAuth()
	if err != nil {
		result.Message = fmt.Sprintf("Error when generating ssh auth: %s", err)
		return
	}

	sshAddress := fmt.Sprintf("%s:%d", definition.Host, definition.Port)

	// Connect with SSh
	sshClient, err := ssh.Dial("tcp", sshAddress, sshConfig)
	if err != nil {
		result.Message = fmt.Sprintf("Failed to connect to %s: %s", sshAddress, err)
		return
	}
	defer func() {
		sshClientCloseErr := sshClient.Close()
		if err == nil && sshClientCloseErr != nil {
			result.Message = fmt.Sprintf("error closing ssh client connection: %s", sshClientCloseErr.Error())
			result.Passed = false
		}
	}()

	// Create SSH session
	sshSession, err := sshClient.NewSession()
	if err != nil {
		result.Message = fmt.Sprintf("Failed to create ssh session: %s", err)
		return
	}
	defer func() {
		sshSessionCloseErr := sshSession.Close()
		if err == nil && sshSessionCloseErr != nil && sshSessionCloseErr.Error() != "EOF" {
			result.Message = fmt.Sprintf("error closing ssh session connection: %s", sshSessionCloseErr.Error())
			result.Passed = false
		}
	}()

	if definition.Command == "" {
		result.Passed = true
		return
	}

	output, err := sshSession.CombinedOutput(definition.Command)
	if err != nil {
		result.Message = fmt.Sprintf("Error executing command: %s", err)
		return
	}

	if definition.MatchContent {
		// Match some content
		regex, err := regexp.Compile(d.ContentRegex)
		if err != nil {
			result.Message = fmt.Sprintf("Error compiling regex string: %s", err)
			return
		}

		// Check if the content matches
		if !regex.Match(output) {
			result.Message = "Matching content not found"
			return
		}
	}

	result.Passed = true
	return
}

func (d Definition) generateAuth() (sshAuth []ssh.AuthMethod, err error) {
	var authMethods []ssh.AuthMethod

	if d.Password != "" {
		authMethods = append(authMethods, ssh.Password(d.Password))
	}

	if d.Key != "" || d.KeyFile != "" {
		var key []byte

		// Read ssh key file
		if d.KeyFile != "" {
			key, err = os.ReadFile(d.KeyFile)
			if err != nil {
				return authMethods, fmt.Errorf("unable to read private key: %v", err)
			}
		} else {
			key = []byte(d.Key)
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
func (d Definition) Validate() (passed bool, message string) {
	if d.Host == "" {
		return false, "Host needs to be defined"
	}

	if d.Username == "" {
		return false, "Username needs to be defined"
	}

	if d.Key != "" && d.KeyFile != "" {
		return false, "Cannot have both Key and KeyFile defined"
	}

	if d.Key == "" && d.KeyFile == "" && d.Password == "" {
		return false, "No authentication method defined"
	}

	return true, ""
}
