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
	Host string
	Port uint16
	Username string
	Password string
	Domain string
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

	var dialTimeout time.Duration
	deadlineTime, okay := ctx.Deadline()
	if okay {
		dialTimeout = time.Until(deadlineTime)
	} else {
		dialTimeout = 10*time.Second
	}

	width, height := 1280, 800
	address := fmt.Sprintf("%s:%d", definition.Host, definition.Port)

	client := grdp.NewRdpClient(address, width, height, func(address string) (net.Conn, error) {
		return net.DialTimeout("tcp", address, dialTimeout)
	})
	defer client.Close()

	client.SetKeyboardLayout("US")

	err = client.Login(definition.Domain, definition.Username, definition.Password)
	if err != nil {
		result.Message = fmt.Sprintf("failed to login: %v", err)
		return
	}

	client.KeyDown(65)

	client.Reconnect(1920, 1080)

	client.MouseMove(1, 1)

	result.Passed = true
	return
}
