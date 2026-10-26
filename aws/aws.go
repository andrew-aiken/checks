package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/andrew-aiken/checks"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type Definition struct {
	// AWS access key
	AccessKey string `json:"accessKey" optiontype:"required"`
	// AWS secret access key
	SecretAccesskey string `json:"secretAccessKey" optiontype:"required"`
	// The expected account id
	Account string `json:"account"`
	// Override the STS endpoint
	Endpoint string `json:"endpoint"`
	// Shared configuration across all checks
	checks.SharedDefinition
}

// Run an AWS check
func (d Definition) Run(ctx context.Context, static checks.StaticConf) (result checks.Results) {
	result = checks.Results{Timestamp: time.Now()}

	// Currently this check cannot actually use the static creds, but keeping it here for consistency
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

	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithCredentialsProvider(credentials.StaticCredentialsProvider{
			Value: aws.Credentials{
				AccessKeyID:     definition.AccessKey,
				SecretAccessKey: definition.SecretAccesskey,
			},
		}))
	if err != nil {
		result.Message = "failed to setup aws credential provider: " + err.Error()
		return
	}

	client := sts.NewFromConfig(cfg, func(o *sts.Options) {
		if definition.Endpoint != "" {
			o.BaseEndpoint = aws.String(definition.Endpoint)
		}
	})
	identity, err := client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		result.Message = "failed to get caller identity: " + err.Error()
		return
	}

	// Don't validate when account id is set to zero
	if definition.Account != "" {
		if aws.ToString(identity.Account) != definition.Account {
			result.Message = "account does not match expected value"
			return
		}
	}

	result.Passed = true
	return
}


// Validats the aws definition
func (d Definition) Validate() (passed bool, message string) {
	if d.AccessKey == "" {
		return false, "Access Key needs to be defined"
	}

	if d.SecretAccesskey == "" {
		return false, "Secret Access Key needs to be defined"
	}

	if d.Account != "" {
		if len(d.Account) != 12 {
			return false, "Account number must be 12 digits"
		}
	}

	return true, ""
}
