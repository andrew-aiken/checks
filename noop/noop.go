package noop

import (
	"context"
	"time"

	"github.com/andrew-aiken/checks"
)

type Definition struct {
	Pass bool `json:"pass" default:"true"` // Whether the check should pass
}

func (d *Definition) Run(ctx context.Context, static checks.StaticConf) checks.Results {
	result := checks.Results{
		Timestamp: time.Now(),
		Passed:    d.Pass,
	}

	return result
}

// Validats the noop definition is valid
func (d *Definition) Validate() (passed bool, message string) {
	return true, ""
}
