package rdp

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/andrew-aiken/checks"

	"github.com/nakagami/grdp"
)

type Definition struct {
	// Server host being connected to
	Host string `json:"host" optiontype:"required"`
	// RDP connection port
	Port uint16 `json:"port" default:"3389"`
	// User connecting to the server
	Username string `json:"username" optiontype:"required"`
	// Users password
	Password string `json:"password" optiontype:"required"`
	// Domain if connecting with an AD user
	Domain string `json:"domain"`
	// Shared configuration across all checks
	checks.SharedDefinition
}

// Run performs an RDP connection check
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

	var dialTimeout time.Duration
	deadlineTime, okay := ctx.Deadline()
	if okay {
		dialTimeout = time.Until(deadlineTime)
	} else {
		dialTimeout = 10 * time.Second
	}

	var width, height = 1920, 1080
	address := fmt.Sprintf("%s:%d", definition.Host, definition.Port)

	client := grdp.NewRdpClient(address, width, height, func(address string) (net.Conn, error) {
		return net.DialTimeout("tcp", address, dialTimeout)
	})
	defer client.Close()

	client.SetKeyboardLayout("US")
	client.DisableAVC444()

	connectionErr := make(chan error, 1)
	reportConnectionErr := func(err error) {
		select {
		case connectionErr <- err:
		default:
		}
	}
	client.OnError(reportConnectionErr)

	err = client.Login(definition.Domain, definition.Username, definition.Password)
	if err != nil {
		result.Message = fmt.Sprintf("failed to login: %v", err)
		return
	}

	checkConnection := func() error {
		select {
		case err := <-connectionErr:
			return err
		default:
			return nil
		}
	}

	time.Sleep(500 * time.Millisecond)
	if err := checkConnection(); err != nil {
		result.Message = fmt.Sprintf("connection encountered errors: %v", err)
		return
	}

	result.Passed = true
	return
}

// Validate checks if the rdp definition is valid
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

	return true, ""
}
