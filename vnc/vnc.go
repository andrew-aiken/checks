package vnc

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/andrew-aiken/checks"

	"github.com/kward/go-vnc"
)

type Definition struct {
	// IP or hostname of the host to run against
	Host string `json:"host" optiontype:"required"`
	// VNC port
	Port uint16 `json:"port" default:"5900"`
	// vnc sessions password
	Password string `json:"password"`
	// Check whether the hostname matches
	MatchHostname string `json:"matchHostname"`
	// Shared configuration across all checks
	checks.SharedDefinition
}

// Run performs a vnc check
func (d Definition) Run(ctx context.Context, static checks.StaticConf) (result checks.Results) {
	result = checks.Results{
		Timestamp: time.Now(),
		Details:   make(map[string]string),
	}

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

	portString := strconv.Itoa(int(definition.Port))
	address := net.JoinHostPort(definition.Host, portString)

	nc, err := net.Dial("tcp", address)
	if err != nil {
		result.Message = fmt.Sprintf("Error connecting to VNC host: %s", err.Error())
		return
	}

	vncConfig := vnc.NewClientConfig(definition.Password)
	vc, err := vnc.Connect(ctx, nc, vncConfig)
	if err != nil {
		result.Message = fmt.Sprintf("Error negotiating connection to VNC host: %s", err.Error())
		return
	}
	defer func() {
		vncCloseErr := vc.Close()
		if err == nil && vncCloseErr != nil {
			result.Message = fmt.Sprintf("Error closing vnc client: %s", vncCloseErr.Error())
			result.Passed = false
		}
	}()

	// Listen and handle server messages.
	go func() {
		vncClientErr := vc.ListenAndHandle()
		if err == nil && vncClientErr != nil {
			result.Message = fmt.Sprintf("Error handling vnc listener: %s", vncClientErr.Error())
			result.Passed = false
		}
	}()

	if definition.MatchHostname != "" {
		// Get the desktop name and split out the hostname
		hostname, _, okay := strings.Cut(vc.DesktopName(), ":")
		if !okay {
			result.Message = "Failed to get hostname"
			return
		}

		if hostname != definition.MatchHostname {
			result.Message = fmt.Sprintf("Hostname does not match, got %s, expected %s", hostname, definition.MatchHostname)
			return
		}
	}

	result.Passed = true
	return
}

// Validate checks if the vnc definition is valid
func (d Definition) Validate() (passed bool, message string) {
	if d.Host == "" {
		return false, "Host needs to be defined"
	}

	return true, ""
}
