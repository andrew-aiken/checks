package checks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"text/template"
	"time"
)

// Checker is the interface that all check types must implement
type Checker interface {
	Run(ctx context.Context, static StaticConf) Results
	Validate() (passed bool, message string)
}

// SharedDefinition are default types embedded into all check definitions
type SharedDefinition struct {
	Timeout int `json:"timeout" default:"10"`
}

// Results is the return type of all checks
type Results struct {
	Details   map[string]string `json:"details"`
	Message   string            `json:"message"`
	Passed    bool              `json:"passed"`
	Timestamp time.Time         `json:"timestamp"`
}

// StaticConf are types that are default accepted to be templated into checks
type StaticConf struct {
	TeamNumber    uint16 // TeamNumber
	TeamNumberHex string // TeamNumberHex
}

// TemplateDefinition templates the check any object with team specific information
func TemplateDefinition(def any, static StaticConf) ([]byte, error) {
	definitionJSON, err := json.Marshal(def)
	if err != nil {
		return nil, fmt.Errorf("error marshaling definition: %s", err)
	}

	tmpl, err := template.New("").Parse(string(definitionJSON))
	if err != nil {
		return nil, err
	}

	var definitionBuffer bytes.Buffer
	err = tmpl.Execute(&definitionBuffer, static)
	if err != nil {
		return nil, err
	}

	return definitionBuffer.Bytes(), nil
}
