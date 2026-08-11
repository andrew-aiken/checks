package smb

import (
	"bytes"
	"context"
	"crypto/sha3"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	"github.com/andrew-aiken/checks"

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/spnego"
)

type Definition struct {
	// IP or hostname of the host to run against
	Host string `json:"host" optiontype:"required"`
	// Command to run if successfully connected with SSH
	File string `json:"file"`
	// Name of the SMB share
	Share string `json:"share" optiontype:"required"`
	// SMB share domain
	Domain string `json:"domain"`
	// SMB port
	Port uint16 `json:"port" default:"445"`
	// User to authenticate with
	Username string `json:"username"`
	// User's password
	Password string `json:"password"`
	// Whether to match the files contents againsta regex
	MatchContent bool `json:"matchContent" default:"false"`
	// regex to match againsts the files contents
	ContentRegex string `json:"contentRegex" default:".*"`
	// Whether or not to match a hash of the file contents
	MatchContentHash bool `json:"matchContentHash" default:"false"`
	// The sha3-256 hash digest of the files text
	Hash string `json:"hash"`
	// Shared configuration across all checks
	checks.SharedDefinition
}

// Run performs a smb check
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

	options := smb.Options{
		Host: definition.Host,
		Port: int(definition.Port),
		Initiator: &spnego.NTLMInitiator{
			User:     definition.Username,
			Password: definition.Password,
			Domain:   definition.Domain,
		},
	}
	session, err := smb.NewConnection(options)
	if err != nil {
		result.Message = fmt.Sprintf("Failed to start smb connection: %s", err)
		return
	}
	defer session.Close()

	err = session.TreeConnect(definition.Share)
	if err != nil {
		result.Message = fmt.Sprintf("Failed to tree connect: %s", err)
		return
	}
	defer session.TreeDisconnect(definition.Share)

	if definition.File != "" {
		var buf bytes.Buffer
		err = session.RetrieveFile(definition.Share, definition.File, 0, func(chunk []byte) (int, error) {
			return buf.Write(chunk)
		})
		if err != nil {
			result.Message = fmt.Sprintf("Failed to read file: %s", err)
			return
		}

		filesBytes := buf.Bytes()

		if definition.MatchContent {
			regex, err := regexp.Compile(definition.ContentRegex)
			if err != nil {
				result.Message = fmt.Sprintf("Error compiling regex string: %s", err)
				return
			}

			if !regex.Match(filesBytes) {
				result.Message = "File contents does not match regex"
				return
			}
		}

		// Compare the files content against as hash
		if definition.MatchContentHash {
			// Get the file contents hash
			digest := sha3.Sum256(filesBytes)

			// Check if the digest of the file matches the defined hash
			if digestString := hex.EncodeToString(digest[:]); digestString != definition.Hash {
				fmt.Println(digestString)
				result.Message = "File content does not match expected hash"
				result.Details["hash"] = digestString
				return
			}
		}
	}

	result.Passed = true
	return
}
