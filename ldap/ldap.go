package ldap

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/andrew-aiken/checks"

	"github.com/go-ldap/ldap/v3"
)

type Definition struct {
	// IP or hostname of the ldap host
	Host string `json:"host" optiontype:"required"`
	// TCP port number to connect to
	Port uint16 `json:"port" default:"389"`
	// Domain of the LDAP server
	// Required when connecting with encryption
	Domain string `json:"domain"`
	// User to login to
	// "cn=admin,dc=example,dc=org" or username only that gets appended with @domain
	Username string `json:"username" optiontype:"required"`
	// The users password
	Password string `json:"password"`
	// If the connection should be encrypted
	Encrypted bool `json:"encrypted" default:"false"`
	// Whether to verify the server's TLS certificate
	SkipVerifyCert bool `json:"skipVerifyCert" default:"false"`
	// Shared configuration across all checks
	checks.SharedDefinition
}

// Run performs a ldap check
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

	address := fmt.Sprintf("ldap://%s:%d", definition.Host, definition.Port)
	conn, err := ldap.DialURL(address)
	if err != nil {
		result.Message = fmt.Sprintf("Failed to dial ldap %s: %s", address, err)
		return
	}
	defer func() {
		connCloseErr := conn.Close()
		if err == nil && connCloseErr != nil {
			result.Message = fmt.Sprintf("error closing ldap connection: %s", connCloseErr.Error())
			result.Passed = false
		}
	}()

	conn.SetTimeout(time.Duration(definition.Timeout) * time.Second)

	if definition.Encrypted {
		tlsConfig := tls.Config{
			ServerName:         definition.Domain,
			InsecureSkipVerify: definition.SkipVerifyCert, // #nosec G402
		}
		err = conn.StartTLS(&tlsConfig)
		if err != nil {
			result.Message = fmt.Sprintf("Failed to setup TLS session: %s", err)
			return
		}
	}

	// Username may already be in LDIF ( "cn=admin,dc=example,dc=org")
	// Otherwise, fall back to the user@domain UPN format.
	account := definition.Username
	if !strings.Contains(account, "=") {
		account = fmt.Sprintf("%s@%s", definition.Username, definition.Domain)
	}

	if definition.Password == "" {
		err = conn.UnauthenticatedBind(account)
		if err != nil {
			result.Message = fmt.Sprintf("Failed to login with user: %s", err)
			return
		}
	} else {
		err = conn.Bind(account, definition.Password)
		if err != nil {
			result.Message = fmt.Sprintf("Failed to login with user: %s", err)
			return
		}
	}

	result.Passed = true
	return
}

// Validate checks if the ldap definition is valid
func (d Definition) Validate() (passed bool, message string) {
	if d.Host == "" {
		return false, "Host needs to be defined"
	}

	if d.Username == "" {
		return false, "Username needs to be defined"
	}

	if d.Domain == "" && d.Encrypted {
		return false, "Domain needs to be set when using encryption"
	}

	if d.Domain == "" && !strings.Contains(d.Username, "=") {
		return false, "Login needs to be set as LDIF or UPN format"
	}

	return true, ""
}
