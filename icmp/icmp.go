package icmp

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/andrew-aiken/checks"

	probing "github.com/prometheus-community/pro-bing"
)

type Definition struct {
	// Pass check based on received pings matching Count; if false, will use percent packet loss
	AllowPacketLoss bool `json:"allowPacketLoss" default:"true"`
	// The number of ICMP requests to send per check
	Count int `json:"count" default:"1"`
	// IP or hostname of the host to run the ICMP check against
	Host string `json:"host" optiontype:"required"`
	// Percent of packets needed to come back to pass the check
	Percent int8 `json:"percent" default:"100"`
	// Shared configuration across all checks
	checks.SharedDefinition
}

func (d Definition) Run(ctx context.Context, static checks.StaticConf) checks.Results {
	// Initialize empty result
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

	// Create pinger
	pinger, err := probing.NewPinger(definition.Host)
	if err != nil {
		result.Message = fmt.Sprintf("Error creating pinger: %s", err)
		return result
	}

	// Send ping
	pinger.Count = definition.Count
	pinger.Timeout = time.Duration(definition.Timeout) * time.Second
	_ = pinger.Run()

	stats := pinger.Statistics()

	details := make(map[string]string)
	// Check packet loss instead of count
	if !definition.AllowPacketLoss {
		if stats.PacketLoss >= float64(definition.Percent) {
			result.Message = "Not all pings made it back!"
			details["packetloss_percent"] = strconv.FormatFloat(stats.PacketLoss, 'f', -1, 64)
			result.Details = details
			return result
		}

		// If we make it here the check passes by percentage
		result.Passed = true
		return result
	}

	// Check for failure of ICMP
	if stats.PacketsRecv != definition.Count {
		result.Message = "Not all pings made it back!"
		details["packets_received"] = fmt.Sprintf("%d", stats.PacketsRecv)
		details["packets_expected"] = fmt.Sprintf("%d", definition.Count)
		result.Details = details
		return result
	}

	// If we make it here the check passes
	result.Passed = true

	return result
}

// Validats the icmp definition is valid
func (d Definition) Validate() (passed bool, message string) {
	if d.Host == "" {
		return false, "Host needs to be defined"
	}

	if d.Count <= 0 {
		return false, "Count must be larger then 0"
	}

	if d.Percent < 0 || d.Percent > 100 {
		return false, "Percent must be between 0 and 100"
	}

	return true, ""
}
