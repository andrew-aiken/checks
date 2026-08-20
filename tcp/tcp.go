package tcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"time"

	"github.com/andrew-aiken/checks"
)

type Definition struct {
	// IP or hostname of the host to run the TCP check against
	Host string `json:"host" optiontype:"required"`
	// TCP port number to connect to
	Port uint16 `json:"port" optiontype:"required"`
	// Whether the connection must match a defined regex for the check to pass
	MatchContent bool `json:"matchContent" default:"false"`
	// Regex to match against the connections results
	ContentRegex string `json:"contentRegex" default:".*"`
	// Message to write to the TCP connection
	Write string `json:"write"`
	// Shared configuration across all checks
	checks.SharedDefinition
}

// Run performs a TCP check
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

	portString := strconv.Itoa(int(definition.Port))
	target := net.JoinHostPort(definition.Host, portString)
	conn, err := net.DialTimeout("tcp", target, time.Duration(definition.Timeout)*time.Second)
	if err != nil {
		result.Message = fmt.Sprintf("Failed to connect: %s", err)
		return
	}
	defer func() {
		connCloseErr := conn.Close()
		if err == nil && connCloseErr != nil {
			result.Message = fmt.Sprintf("error closing tcp connection: %s", connCloseErr.Error())
			result.Passed = false
		}
	}()

	if definition.Write != "" {
		_, err := conn.Write([]byte(definition.Write))
		if err != nil {
			result.Message = fmt.Sprintf("Failed to write to connection: %s", err)
			return
		}
	}

	if definition.MatchContent {
		data := make([]byte, 2048)
		length, err := conn.Read(data)
		if err != nil {
			result.Message = fmt.Sprintf("Error reading from connection: %s", err)
			return
		}

		regex, err := regexp.Compile(definition.ContentRegex)
		if err != nil {
			result.Message = fmt.Sprintf("Error compiling regex string: %s", err)
			return
		}

		if !regex.Match(data[:length]) {
			result.Message = "File contents does not match regex"
			return
		}
	}

	result.Passed = true
	return
}

// Validate checks if the tcp definition is valid
func (d Definition) Validate() (passed bool, message string) {
	if d.Host == "" {
		return false, "Host needs to be defined"
	}

	if d.Port == 0 {
		return false, "Port needs to be defined"
	}

	if d.MatchContent && d.ContentRegex != "" {
		if _, err := regexp.Compile(d.ContentRegex); err != nil {
			return false, "Failed to compile regex"
		}
	}

	return true, ""
}
