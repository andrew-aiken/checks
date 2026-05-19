package dns

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/andrew-aiken/checks"

	"github.com/miekg/dns"
)

// The Definition configures the behavior of the DNS check
// it implements the "check" interface
type Definition struct {
	Server         string `json:"server" optiontype:"required"`         // The IP of the DNS server to query
	Fqdn           string `json:"fqdn" optiontype:"required"`           // The FQDN of the host you are looking up
	ExpectedResult string `json:"expectedResult" optiontype:"required"` // The expected IP of the host you are looking up
	Port           uint16 `json:"port" default:"53"`                    // The port of the DNS server
	RecordType     string `json:"recordType" default:"A"`               // The type of DNS record to query
	Timeout        uint8  `json:"timeout" default:"20"`                 // Timeout for the dns query in seconds
}

// Run a single instance of the check
func (d *Definition) Run(ctx context.Context, static checks.StaticConf) checks.Results {
	// Initialize empty result
	result := checks.Results{Timestamp: time.Now()}

	recordType, ok := dns.StringToType[d.RecordType]
	if !ok {
		result.Message = fmt.Sprintf("Unknown record type: %s", d.RecordType)
		return result
	}

	// Setup for dns query
	var msg dns.Msg
	msg.SetQuestion(dns.Fqdn(d.Fqdn), recordType)

	// Make it obey timeout via deadline
	deadctx, cancel := context.WithDeadline(ctx, time.Now().Add(time.Duration(d.Timeout)*time.Second))
	defer cancel()

	// Send the query
	in, err := dns.ExchangeContext(deadctx, &msg, fmt.Sprintf("%s:%d", d.Server, d.Port))
	if err != nil {
		result.Message = fmt.Sprintf("Problem sending query to %s : %s", d.Server, err)
		return result
	}

	// Check if we got any records
	if len(in.Answer) < 1 {
		result.Message = fmt.Sprintf("No records received from %s", d.Server)
		return result
	}

	// Loop through results and check for correct match
	for _, answer := range in.Answer {
		if answer.Header().Rrtype != recordType {
			continue
		}

		// Extract record value by parsing the string format: name\tttl\tclass\ttype\tvalue
		parts := strings.SplitN(answer.String(), "\t", 5)

		if len(parts) >= 5 && strings.Trim(parts[4], "\"") == d.ExpectedResult {
			result.Passed = true
			return result
		}
	}

	// If we reach here no records matched expected IP and check fails
	result.Message = "Incorrect Records Returned"
	return result
}

// Validats the dns definition is valid
func (d *Definition) Validate() (passed bool, message string) {
	if d.Server == "" {
		return false, "Server needs to be defined"
	}

	if d.Fqdn == "" {
		return false, "FQDN needs to be defined"
	}

	if d.ExpectedResult == "" {
		return false, "Expected result needs to be defined"
	}

	return true, ""
}
