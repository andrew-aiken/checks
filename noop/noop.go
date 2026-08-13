package noop

import (
	"context"
	"time"

	"github.com/andrew-aiken/checks"
)

type Definition struct {
	// Whether the check should pass
	Pass bool `json:"pass" default:"true"`
	// Shared configuration across all checks
	checks.SharedDefinition
}

// Run performs a noop check
func (d Definition) Run(ctx context.Context, static checks.StaticConf) (result checks.Results) {
	return checks.Results{
		Timestamp: time.Now(),
		Passed:    d.Pass,
	}
}

// Validats the noop definition is valid
func (d Definition) Validate() (passed bool, message string) {
	return true, ""
}
