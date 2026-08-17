package snmp_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/andrew-aiken/checks"
	"github.com/andrew-aiken/checks/snmp"

	"github.com/gosnmp/gosnmp"
	"github.com/slayercat/GoSNMPServer"
)

func TestSNMTP(t *testing.T) {
	oid := "1.2.3.4.5.6.7.8.9"
	oidResult := "snmpResponse"
	var port uint16 = 1161
	host := "127.0.0.1"
	communityString := "public"

	username := "username"
	authPassword := "auth"
	privacyPassword := "privacy"

	server := GoSNMPServer.NewSNMPServer(GoSNMPServer.MasterAgent{
		SecurityConfig: GoSNMPServer.SecurityConfig{
			NoSecurity:               true,
			AuthoritativeEngineBoots: 1,
			Users: []gosnmp.UsmSecurityParameters{
				{
					UserName:                 username,
					AuthenticationProtocol:   gosnmp.SHA,
					AuthenticationPassphrase: authPassword,
					PrivacyProtocol:          gosnmp.DES,
					PrivacyPassphrase:        privacyPassword,
				},
			},
		},
		SubAgents: []*GoSNMPServer.SubAgent{
			{
				CommunityIDs: []string{"", communityString},
				OIDs: []*GoSNMPServer.PDUValueControlItem{
					{
						OID:      oid,
						Type:     gosnmp.OctetString,
						OnGet:    func() (value any, err error) { return GoSNMPServer.Asn1OctetStringWrap(oidResult), nil },
						Document: "ifIndex",
					},
				},
			},
		},
	})

	address := fmt.Sprintf("%s:%d", host, port)
	err := server.ListenUDP("udp", address)
	if err != nil {
		t.Fatalf("Error in listen: %+v", err)
	}
	go func() {
		err := server.ServeForever()
		if err != nil {
			fmt.Printf("Error serving snmp: %s\n", err.Error())
		}
	}()
	defer server.Shutdown()

	time.Sleep(500 * time.Millisecond)

	staticConfig := checks.StaticConf{}

	tests := []struct {
		Name             string
		Definition       snmp.Definition
		Result           checks.Results
		MessageSubstring string
	}{
		{
			Name: "Validv3",
			Definition: snmp.Definition{
				Host:              host,
				Port:              port,
				OID:               oid,
				MatchContent:      true,
				ContentRegex:      oidResult,
				Username:          username,
				AuthPassphrase:    authPassword,
				PrivacyPassphrase: privacyPassword,
				Version:           "3",
				Retries:           3,
				SharedDefinition: checks.SharedDefinition{
					Timeout: 3,
				},
			},
			Result: checks.Results{
				Passed: true,
			},
		},
		{
			Name: "Validv2c",
			Definition: snmp.Definition{
				Host:            host,
				Port:            port,
				CommunityString: communityString,
				OID:             oid,
				Version:         "2c",
				Retries:         3,
				SharedDefinition: checks.SharedDefinition{
					Timeout: 3,
				},
			},
			Result: checks.Results{
				Passed: true,
			},
		},
		{
			Name: "InvalidTemplate",
			Definition: snmp.Definition{
				Host:     host,
				Port:     port,
				OID:      "{{",
				Username: username,
				Version:  "3",
				Retries:  1,
				SharedDefinition: checks.SharedDefinition{
					Timeout: 3,
				},
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "internal error templating definition:",
		},
		{
			Name: "UnknownSNMPVersion",
			Definition: snmp.Definition{
				Host:    host,
				Port:    port,
				OID:     oid,
				Version: "4",
				Retries: 1,
				SharedDefinition: checks.SharedDefinition{
					Timeout: 3,
				},
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Unknown snmp version: 4",
		},
		{
			Name: "ConnectionFail",
			Definition: snmp.Definition{
				Host:    host,
				Port:    port,
				OID:     oid,
				Version: "3",
				Retries: 1,
				SharedDefinition: checks.SharedDefinition{
					Timeout: 1,
				},
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Failed to connect: securityParameters.UserName is required",
		},
		{
			Name: "ConnectionTimeout",
			Definition: snmp.Definition{
				Host:            host,
				Port:            port + 1,
				CommunityString: communityString,
				OID:             oid,
				Version:         "2c",
				Retries:         1,
				SharedDefinition: checks.SharedDefinition{
					Timeout: 1,
				},
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Failed to get OID:",
		},
		{
			Name: "InvalidRegex",
			Definition: snmp.Definition{
				Host:           host,
				Port:           port,
				OID:            oid,
				MatchContent:   true,
				ContentRegex:   "[a-z",
				Username:       username,
				AuthPassphrase: authPassword,
				Version:        "3",
				Retries:        1,
				SharedDefinition: checks.SharedDefinition{
					Timeout: 3,
				},
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Error compiling regex string:",
		},
		{
			Name: "MissedRegex",
			Definition: snmp.Definition{
				Host:         host,
				Port:         port,
				OID:          oid,
				MatchContent: true,
				ContentRegex: "dne",
				Username:     username,
				Version:      "3",
				Retries:      1,
				SharedDefinition: checks.SharedDefinition{
					Timeout: 3,
				},
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Response contents does not match regex",
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			ctx := context.Background()
			timeoutContext, cxtCancel := context.WithTimeout(ctx, 3*time.Second)
			defer cxtCancel()

			result := tt.Definition.Run(timeoutContext, staticConfig)

			if result.Passed != tt.Result.Passed {
				t.Fatalf("Check does not match expected result: test(%q) got %t", tt.Name, result.Passed)
			}

			if tt.MessageSubstring != "" && !strings.Contains(result.Message, tt.MessageSubstring) {
				t.Fatalf("Expected message substring %q for check(%q), got message %q", tt.MessageSubstring, tt.Name, result.Message)
			}
		})
	}
}

func TestSNMPValidate(t *testing.T) {
	tests := []struct {
		Name            string
		Definition      snmp.Definition
		ValidateMessage string
	}{
		{
			Name: "Valid",
			Definition: snmp.Definition{
				Host:         "host",
				OID:          "1.2.3",
				MatchContent: true,
				ContentRegex: ".*",
				Username:     "dummy",
				Version:      "3",
			},
		},
		{
			Name: "MissingHost",
			Definition: snmp.Definition{
				// Host: "host",
				OID:      "1.2.3",
				Username: "dummy",
				Version:  "3",
			},
			ValidateMessage: "Host needs to be defined",
		},
		{
			Name: "MissingOID",
			Definition: snmp.Definition{
				Host: "host",
				// OID: "1.2.3",
				Username: "dummy",
				Version:  "3",
			},
			ValidateMessage: "OID needs to be defined",
		},
		{
			Name: "InvalidVersion",
			Definition: snmp.Definition{
				Host:    "host",
				OID:     "1.2.3",
				Version: "4",
			},
			ValidateMessage: "Invalid SNMP version specified",
		},
		{
			Name: "InvalidV3Config",
			Definition: snmp.Definition{
				Host:    "host",
				OID:     "1.2.3",
				Version: "3",
			},
			ValidateMessage: "Username needs to be specified when using SNMPv3",
		},
		{
			Name: "InvalidRegex",
			Definition: snmp.Definition{
				Host:         "host",
				OID:          "1.2.3",
				Version:      "2c",
				MatchContent: true,
				ContentRegex: "[a-z",
			},
			ValidateMessage: "Failed to compile regex",
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			_, message := tt.Definition.Validate()
			if message != tt.ValidateMessage {
				t.Fatalf("Validate message does not match expected message(%q): got %q want %q", tt.Name, message, tt.ValidateMessage)
			}
		})
	}
}
