package ftp

import (
	"context"
	"crypto/sha3"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"time"

	"github.com/andrew-aiken/checks"

	"github.com/jlaffaye/ftp"
)

type Definition struct {
	// IP or FQDN of the FTP server
	Host string `json:"host" optiontype:"required"`
	// TCP port number the FTP server is listening on
	Port uint16 `json:"port" default:"21"`
	// User that connects to the FTP server
	Username string `json:"username" optiontype:"required"`
	// The users password
	Password string `json:"password"`
	// Whether to secure the control and data connections with explicit TLS (FTPS, AUTH TLS)
	TLS bool `json:"tls" default:"false"`
	// Whether to skip verification of the server's TLS certificate
	TLSSkipVerify bool `json:"tlsSkipVerify" default:"false"`
	// File to retrieve from the server
	// If empty just check the FTP connection
	File string `json:"file"`
	// Whether the file must match a defined regex for the check to pass
	MatchContent bool `json:"matchContent" default:"false"`
	// Regex to match against the returned file
	ContentRegex string `json:"contentRegex" default:".*"`
	// Whether or not to match a hash of the file contents
	MatchContentHash bool `json:"matchContentHash" default:"false"`
	// The sha3-256 hash digest of the files text
	Hash string `json:"hash"`
	// Shared configuration across all checks
	checks.SharedDefinition
}

// Run performs a FTP check
func (d Definition) Run(ctx context.Context, static checks.StaticConf) (result checks.Results) {
	result = checks.Results{
		Timestamp: time.Now(),
		Details:   make(map[string]string),
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

	connectionString := fmt.Sprintf("%s:%d", definition.Host, definition.Port)
	dialOptions := []ftp.DialOption{ftp.DialWithContext(ctx)}
	if definition.TLS {
		tlsConfig := &tls.Config{
			ServerName:         definition.Host,
			InsecureSkipVerify: definition.TLSSkipVerify, // #nosec G402
		}
		dialOptions = append(dialOptions, ftp.DialWithExplicitTLS(tlsConfig))
	}
	conn, err := ftp.Dial(connectionString, dialOptions...)
	if err != nil {
		result.Message = fmt.Sprintf("Connection to %s on port %d failed: '%s'", definition.Host, definition.Port, err)
		return
	}
	defer conn.Quit()

	err = conn.Login(definition.Username, definition.Password)
	if err != nil {
		result.Message = fmt.Sprintf("Login attempt with user %s failed: %s", definition.Username, err)
		return
	}

	// If no file is specified pass the check
	if definition.File == "" {
		result.Passed = true
		return
	}

	// Retrieve file contents
	resp, err := conn.Retr(definition.File)
	if err != nil {
		result.Message = fmt.Sprintf("Could not retrieve file %s : %s", definition.File, err)
		return
	}
	defer resp.Close()

	content, err := io.ReadAll(resp)
	if err != nil {
		result.Message = fmt.Sprintf("Could not read file %s contents : %s", definition.File, err)
		return
	}

	// Compare the files content against a regular expression
	if definition.MatchContent {
		regex, err := regexp.Compile(definition.ContentRegex)
		if err != nil {
			result.Message = fmt.Sprintf("Error compiling regex string: %s", err)
			return
		}
		if !regex.Match(content) {
			result.Message = "File contents does not match regex"
			return
		}
	}

	// Compare the files content against as hash
	if definition.MatchContentHash {
		// Get the file hash
		digest := sha3.Sum256(content)

		// Check if the digest of the file matches the defined hash
		if digestString := hex.EncodeToString(digest[:]); digestString != definition.Hash {
			result.Message = "File content does not match hash"
			result.Details["hash"] = digestString
			return
		}
	}

	result.Passed = true
	return
}

// Validate checks if the ftp definition is valid
func (d Definition) Validate() (passed bool, message string) {
	if d.Host == "" {
		return false, "Host needs to be defined"
	}

	if d.Username == "" {
		return false, "Username needs to be defined"
	}

	if d.MatchContent && d.ContentRegex != "" {
		if _, err := regexp.Compile(d.ContentRegex); err != nil {
			return false, "Failed to compile regex"
		}
	}

	return true, ""
}
