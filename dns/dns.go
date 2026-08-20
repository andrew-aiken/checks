package dns

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/andrew-aiken/checks"

	"github.com/miekg/dns"
)

// Definition configures the behavior of the DNS check in the "check" interface
type Definition struct {
	// The IP of the DNS server to query
	Server string `json:"server" optiontype:"required"`
	// The FQDN of the host being looking up
	Domain string `json:"domain" optiontype:"required"`
	// The expected response data
	ExpectedResult string `json:"expectedResult" optiontype:"required"`
	// The port of the DNS server
	Port uint16 `json:"port" default:"53"`
	// The type of DNS record to query
	RecordType string `json:"recordType" default:"A"`
	// Shared configuration across all checks
	checks.SharedDefinition
}

// Run a single instance of the check
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

	recordType, ok := dns.StringToType[definition.RecordType]
	if !ok {
		result.Message = fmt.Sprintf("Unknown record type: %s", definition.RecordType)
		return
	}

	// Setup for dns query
	var msg dns.Msg
	msg.SetQuestion(dns.Fqdn(definition.Domain), recordType)

	// Make it obey timeout via deadline
	deadctx, cancel := context.WithDeadline(ctx, time.Now().Add(time.Duration(definition.Timeout)*time.Second))
	defer cancel()

	// Send the query
	in, err := dns.ExchangeContext(deadctx, &msg, fmt.Sprintf("%s:%d", definition.Server, definition.Port))
	if err != nil {
		result.Message = fmt.Sprintf("Problem sending query to %s : %s", definition.Server, err)
		return
	}

	// Check if we got any records
	if len(in.Answer) < 1 {
		result.Message = fmt.Sprintf("No records received from %s", definition.Server)
		return
	}

	// Loop through results and check for correct match
	for _, answer := range in.Answer {
		if answer.Header().Rrtype != recordType {
			continue
		}

		// Extract record value by parsing the string format: name\tttl\tclass\ttype\tvalue
		parts := strings.SplitN(answer.String(), "\t", 5)

		if len(parts) >= 5 && strings.Trim(parts[4], "\"") == definition.ExpectedResult {
			result.Passed = true
			return
		}
	}

	// If we reach here no records matched expected IP and check fails
	result.Message = "Incorrect Records Returned"
	return
}

// Validats the dns definition is valid
func (d Definition) Validate() (passed bool, message string) {
	if d.Server == "" {
		return false, "Server needs to be defined"
	}

	if d.Domain == "" {
		return false, "Domain needs to be defined"
	}

	if d.ExpectedResult == "" {
		return false, "Expected result needs to be defined"
	}

	return true, ""
}
