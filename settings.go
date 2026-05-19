package checks

import (
	"bytes"
	"encoding/json"
	"fmt"
	"text/template"
)

type StaticConf struct {
	// Add fields for static configuration here
	TeamNumber    int16  // TeamNumber
	TeamNumberHex string // TeamNumberHex
}

// Templates the check object with team specific information
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
