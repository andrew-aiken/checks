package s3

import (
	"context"
	"crypto/sha3"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"

	"github.com/andrew-aiken/checks"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

type Definition struct {
	// IP or FQDN of the S3 endpoint
	Host string `json:"host" optiontype:"required"`
	// TCP port the server is listening on, defaults to the protocol's standard port
	Port uint16 `json:"port"`
	// Name of the bucket to check
	Bucket string `json:"bucket" optiontype:"required"`
	// Access key ID to authenticate with
	AccessKey string `json:"accessKey"`
	// Secret access key to authenticate with
	SecretKey string `json:"secretKey"`
	// Region the bucket is located in
	Region string `json:"region" default:"us-east-1"`
	// Whether to connect to the S3 endpoint over HTTPS
	TLS bool `json:"tls" default:"false"`
	// Whether to skip verification of the server's TLS certificate
	TLSSkipVerify bool `json:"tlsSkipVerify" default:"false"`
	// Object key to retrieve from the bucket
	Object string `json:"object"`
	// Whether the object must match a defined regex for the check to pass
	MatchContent bool `json:"matchContent" default:"false"`
	// Regex to match against the returned object
	ContentRegex string `json:"contentRegex" default:".*"`
	// Whether or not to match a hash of the object contents
	MatchContentHash bool `json:"matchContentHash" default:"false"`
	// The sha3-256 hash digest of the objects contents
	Hash string `json:"hash"`
	// Shared configuration across all checks
	checks.SharedDefinition
}

// Run performs a S3 check
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

	endpoint := definition.Host
	if definition.Port != 0 {
		endpoint = fmt.Sprintf("%s:%d", definition.Host, definition.Port)
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	if definition.TLS {
		transport.TLSClientConfig = &tls.Config{
			ServerName:         definition.Host,
			InsecureSkipVerify: definition.TLSSkipVerify, // #nosec G402
		}
	}

	client, err := minio.New(endpoint, &minio.Options{
		Creds:      credentials.NewStaticV4(definition.AccessKey, definition.SecretKey, ""),
		Secure:     definition.TLS,
		Region:     definition.Region,
		Transport:  transport,
		MaxRetries: 1,
	})
	if err != nil {
		result.Message = fmt.Sprintf("Failed to create S3 client: %s", err)
		return
	}

	// List a single object to verify the bucket exists and is accessible
	listCtx, cancelList := context.WithCancel(ctx)
	defer cancelList()
	if listed, ok := <-client.ListObjects(listCtx, definition.Bucket, minio.ListObjectsOptions{MaxKeys: 1}); ok && listed.Err != nil {
		result.Message = fmt.Sprintf("Could not access bucket %s: %s", definition.Bucket, listed.Err)
		return
	}

	// If no object is specified pass the check
	if definition.Object == "" {
		result.Passed = true
		return
	}

	// Retrieve object contents
	object, err := client.GetObject(ctx, definition.Bucket, definition.Object, minio.GetObjectOptions{})
	if err != nil {
		result.Message = fmt.Sprintf("Could not retrieve object %s: %s", definition.Object, err)
		return
	}
	defer func() {
		objectCloseErr := object.Close()
		if err == nil && objectCloseErr != nil {
			result.Message = fmt.Sprintf("error closing s3 object: %s", objectCloseErr.Error())
			result.Passed = false
		}
	}()

	content, err := io.ReadAll(object)
	if err != nil {
		result.Message = fmt.Sprintf("Could not retrieve object %s: %s", definition.Object, err)
		return
	}

	// Compare the objects content against a regular expression
	if definition.MatchContent {
		regex, err := regexp.Compile(definition.ContentRegex)
		if err != nil {
			result.Message = fmt.Sprintf("Error compiling regex string: %s", err)
			return
		}
		if !regex.Match(content) {
			result.Message = "Object contents does not match regex"
			return
		}
	}

	// Compare the objects content against as hash
	if definition.MatchContentHash {
		digest := sha3.Sum256(content)

		if digestString := hex.EncodeToString(digest[:]); digestString != definition.Hash {
			result.Message = "Object content does not match hash"
			result.Details["hash"] = digestString
			return
		}
	}

	result.Passed = true
	return
}

// Validate the S3 definition
func (d Definition) Validate() (passed bool, message string) {
	if d.Host == "" {
		return false, "Host needs to be defined"
	}

	if d.Bucket == "" {
		return false, "Bucket needs to be defined"
	}

	if d.MatchContent && d.ContentRegex != "" {
		if _, err := regexp.Compile(d.ContentRegex); err != nil {
			return false, "Failed to compile regex"
		}
	}

	return true, ""
}
