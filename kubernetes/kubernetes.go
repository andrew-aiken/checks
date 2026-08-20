package kubernetes

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"slices"
	"strconv"
	"time"

	"github.com/andrew-aiken/checks"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type Definition struct {
	// IP or hostname of the kubernetes apiserver
	Host string `json:"host" optiontype:"required"`
	// Kubernetes apiserver port
	Port uint16 `json:"port" default:"6443"`
	// User to authenticate with
	Username string `json:"username"`
	// Users password
	Password string `json:"password"`
	// Token for bearer authentication
	Token string `json:"token"`
	// Skip validation of the servers certificate
	TLSSkipVerify bool `json:"tlsSkipVerify" default:"false"`
	// Base64 encoded server certificate
	CABase64 string `json:"caBase64"`
	// Base64 encoded client key
	KeyBase64 string `json:"keyBase64"`
	// Base64 encoded client certificate
	CertBase64 string `json:"certBase64"`
	// Just the minor version of the apiserver
	MatchMinorVersion string `json:"matchMinorVersion"`
	// Additional simple check against an API. Currently only namespace and pod are supported
	// These perform a list of the resource
	Query string `json:"query"`
	// Shared configuration across all checks
	checks.SharedDefinition
}

// Run performs a kubernetes check
func (d Definition) Run(ctx context.Context, static checks.StaticConf) (result checks.Results) {
	result = checks.Results{
		Timestamp: time.Now(),
		Details:   make(map[string]string),
	}

	definitionBytes, err := checks.TemplateDefinition(d, static)
	if err != nil {
		result.Message = fmt.Sprintf("internal error templating definition: %s", err.Error())
		return
	}

	var definition Definition
	err = json.Unmarshal(definitionBytes, &definition)
	if err != nil {
		result.Message = fmt.Sprintf("internal error unmarshaling templated definition: %s", err.Error())
		return
	}

	var ca []byte
	if definition.CABase64 != "" {
		ca, err = base64.StdEncoding.DecodeString(definition.CABase64)
		if err != nil {
			result.Message = fmt.Sprintf("Failed to decode root ca certificate: %s", err.Error())
			return
		}
	}

	var key []byte
	if definition.KeyBase64 != "" {
		key, err = base64.StdEncoding.DecodeString(definition.KeyBase64)
		if err != nil {
			result.Message = fmt.Sprintf("Failed to decode key: %s", err.Error())
			return
		}
	}

	var cert []byte
	if definition.CertBase64 != "" {
		cert, err = base64.StdEncoding.DecodeString(definition.CertBase64)
		if err != nil {
			result.Message = fmt.Sprintf("Failed to decode client certificate: %s", err.Error())
			return
		}
	}

	portString := strconv.Itoa(int(definition.Port))
	address := net.JoinHostPort(definition.Host, portString)

	config := &rest.Config{
		// UserAgent: "",
		Host:        address,
		Username:    definition.Username,
		Password:    definition.Password,
		BearerToken: definition.Token,
		Timeout:     time.Duration(definition.Timeout),
		TLSClientConfig: rest.TLSClientConfig{
			Insecure:   definition.TLSSkipVerify, // #nosec G402
			ServerName: definition.Host,
			CertData:   cert,
			KeyData:    key,
			CAData:     ca,
		},
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		result.Message = fmt.Sprintf("Failed to generate client configuration: %s", err.Error())
		return
	}

	ver, err := client.ServerVersion()
	if err != nil {
		result.Message = fmt.Sprintf("Failed to connect to apiserver to retrieve version: %s", err.Error())
		return
	}

	if definition.MatchMinorVersion != "" && ver.Minor != definition.MatchMinorVersion {
		result.Message = fmt.Sprintf("Got wrong apiserver minor version: expected %s, got %s", definition.MatchMinorVersion, ver.Minor)
		return
	}

	var queryErr error = nil
	switch definition.Query {
	case "namespace":
		_, queryErr = client.CoreV1().Namespaces().List(ctx, v1.ListOptions{})
	case "pod":
		_, queryErr = client.CoreV1().Pods("").List(ctx, v1.ListOptions{})
	// Query not specified or unknown
	case "":
	default:
	}

	if queryErr != nil {
		result.Message = fmt.Sprintf("Failed to perform query: %s", queryErr.Error())
		result.Details["query"] = definition.Query
		return
	}

	result.Passed = true
	return
}

// Validate checks if the kubernetes definition is valid
func (d Definition) Validate() (passed bool, message string) {
	if d.Host == "" {
		return false, "Host needs to be defined"
	}

	items := []string{"", "namespace", "pod"}
	if !slices.Contains(items, d.Query) {
		return false, "Invalid query option specified"
	}

	return true, ""
}
