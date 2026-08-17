package snmp

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/andrew-aiken/checks"

	"github.com/gosnmp/gosnmp"
)

type Definition struct {
	// IP or hostname of the system
	Host string `json:"host" optiontype:"required"`
	// snmp udp port
	Port uint16 `json:"port" default:"161"`
	// Object identifier to request
	OID string `json:"oid" optiontype:"required"`
	// Community string
	CommunityString string `json:"communityString"`
	// Username for SNMPv3 authentication
	Username string `json:"username"`
	// Authentication passphrase for SNMPv3
	AuthPassphrase string `json:"authPassphrase"`
	// Privacy passphrase for SNMPv3
	PrivacyPassphrase string `json:"privacyPassphrase"`
	// Amount of retries for the connection
	Retries uint16 `json:"retries" default:"1"`
	// SNMP version to connect with; 1, 2c, 3
	Version string `json:"version" default:"3"`
	// Whether the connection must match a defined regex for the check to pass
	MatchContent bool `json:"matchContent" default:"false"`
	// Regex to match against the OID query result
	ContentRegex string `json:"contentRegex" default:".*"`
	// Shared configuration across all checks
	checks.SharedDefinition
}

// Run performs a snmp check
func (d Definition) Run(ctx context.Context, static checks.StaticConf) (result checks.Results) {
	result = checks.Results{
		Timestamp: time.Now(),
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

	handler := &gosnmp.GoSNMP{
		Target:             definition.Host,
		Port:               definition.Port,
		Retries:            int(definition.Retries),
		Timeout:            time.Duration(definition.Timeout) * time.Second,
		Community:          definition.CommunityString,
		Transport:          "udp",
		Context:            ctx,
		ExponentialTimeout: false,
	}

	// Setup the different SNMP version parameters
	switch definition.Version {
	case "1":
		handler.Version = gosnmp.Version1
	case "2c":
		handler.Version = gosnmp.Version2c
	case "3":
		handler.Version = gosnmp.Version3
		handler.SecurityModel = gosnmp.UserSecurityModel
		// Buildout the v3 authentication object
		authType, securityParams := buildAuth(definition.AuthPassphrase, definition.PrivacyPassphrase)
		securityParams.UserName = definition.Username
		handler.SecurityParameters = securityParams
		handler.MsgFlags = authType
	default:
		result.Message = fmt.Sprintf("Unknown snmp version: %s", definition.Version)
		return
	}

	err = handler.Connect()
	if err != nil {
		result.Message = fmt.Sprintf("Failed to connect: %s", err.Error())
		return
	}

	defer func() {
		handlerCloseErr := handler.Close()
		if err == nil && handlerCloseErr != nil {
			result.Message = fmt.Sprintf("Error closing snmp handler: %s", handlerCloseErr.Error())
			result.Passed = false
		}
	}()

	oids := []string{definition.OID}
	packet, err := handler.Get(oids)
	if err != nil {
		result.Message = fmt.Sprintf("Failed to get OID: %s", err.Error())
		return
	}

	variable := packet.Variables[0]

	var data []byte
	switch variable.Type {
	case gosnmp.OctetString:
		data = variable.Value.([]byte)
	default:
		data = gosnmp.ToBigInt(variable.Value).Bytes()
	}

	if definition.MatchContent {
		regex, err := regexp.Compile(definition.ContentRegex)
		if err != nil {
			result.Message = fmt.Sprintf("Error compiling regex string: %s", err)
			return
		}

		if !regex.Match(data) {
			result.Message = "Response contents does not match regex"
			return
		}
	}

	result.Passed = true
	return
}

// buildAuth takes in authentication and privacy values and returns the correct type of SNMPv3 auth message flag and parameters
func buildAuth(auth string, privacy string) (gosnmp.SnmpV3MsgFlags, *gosnmp.UsmSecurityParameters) {
	config := &gosnmp.UsmSecurityParameters{}

	if auth != "" {
		config.AuthenticationProtocol = gosnmp.SHA
		config.AuthenticationPassphrase = auth
		if privacy != "" {
			config.PrivacyProtocol = gosnmp.DES
			config.PrivacyPassphrase = privacy
			return gosnmp.AuthPriv, config
		}
		return gosnmp.AuthNoPriv, config
	}

	return gosnmp.NoAuthNoPriv, config
}

// Validate checks if the snmp definition is valid
func (d Definition) Validate() (passed bool, message string) {
	if d.Host == "" {
		return false, "Host needs to be defined"
	}

	if d.OID == "" {
		return false, "OID needs to be defined"
	}

	versions := []string{"", "1", "2c", "3"}
	if !slices.Contains(versions, d.Version) {
		return false, "Invalid SNMP version specified"
	}

	if d.Version == "3" && d.Username == "" {
		return false, "Username needs to be specified when using SNMPv3"
	}

	if d.MatchContent && d.ContentRegex != "" {
		if _, err := regexp.Compile(d.ContentRegex); err != nil {
			return false, "Failed to compile regex"
		}
	}

	return true, ""
}
