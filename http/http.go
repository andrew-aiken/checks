package http

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"regexp"
	"strings"
	"time"

	"github.com/andrew-aiken/checks"
)

type Definition struct {
	// IP or FQDN of the HTTP server
	Host string `json:"host" optiontype:"required"`
	// Path to request
	Path string `json:"path" default:"/"`
	// If HTTPS is to be used
	HTTPS bool `json:"https" default:"false"`
	// TCP port number the HTTP server is listening on
	Port uint16 `json:"port" default:"80"`
	// HTTP method to use
	Method string `json:"method" default:"GET"`
	// The response status code to match
	Code uint16 `json:"code" default:"200"`
	// Regex for the response body to match
	ContentRegex string `json:"contentRegex" default:".*"`
	// Name-value pairs of header fields to add/override
	Headers map[string]string `json:"headers"`
	// The request body
	Body string `json:"body"`
	// Whether the response code must match a defined value for the check to pass
	MatchCode bool `json:"matchCode"`
	// Whether the response body must match a defined regex for the check to pass
	MatchContent bool `json:"matchContent"`
	// Whether to follow http redirects
	Redirect bool `json:"redirect"`
	// Whether to verify the server's TLS certificate
	VerifyCert bool `json:"verifyCert"`
	// Shared configuration across all checks
	checks.SharedDefinition
}

func (d Definition) Run(ctx context.Context, static checks.StaticConf) (result checks.Results) {
	result = checks.Results{Timestamp: time.Now()}

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

	// Configure HTTP client
	cookieJar, err := cookiejar.New(nil)
	if err != nil {
		result.Message = "Could not create CookieJar"
		return
	}

	var redirect func(req *http.Request, via []*http.Request) error

	// If redirects are not allowed, set the redirect function to prevent following them
	if !definition.Redirect {
		redirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	client := &http.Client{
		Jar: cookieJar,
		Transport: &http.Transport{
			IdleConnTimeout: 10 * time.Second,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: !definition.VerifyCert, // #nosec G402
			},
		},
		CheckRedirect: redirect,
		Timeout:       time.Duration(definition.Timeout) * time.Second,
	}

	pass, err := definition.request(ctx, client)

	// Process request results
	result.Passed = pass
	if err != nil {
		result.Message = fmt.Sprintf("%s", err)
	}

	return
}

func (d Definition) request(ctx context.Context, client *http.Client) (success bool, requestError error) {
	success = false
	requestError = nil

	// Construct URL
	var schema string
	if d.HTTPS {
		schema = "https"
	} else {
		schema = "http"
	}

	url := fmt.Sprintf("%s://%s:%d%s", schema, d.Host, d.Port, d.Path)
	if d.Redirect {
		url = fmt.Sprintf("%s://%s%s", schema, d.Host, d.Path)
	}

	// Construct request
	req, err := http.NewRequestWithContext(ctx, d.Method, url, strings.NewReader(d.Body))
	if err != nil {
		requestError = fmt.Errorf("error constructing request: %w", err)
		return
	}

	// Handle Host header specially if present
	if h, exists := d.Headers["Host"]; exists {
		req.Host = h
		delete(d.Headers, "Host")
	}

	// Add headers
	for k, v := range d.Headers {
		req.Header[k] = []string{v}
	}

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		requestError = fmt.Errorf("error making request: %w", err)
		return
	}
	defer func() {
		respBodyCloseErr := resp.Body.Close()
		if err == nil && respBodyCloseErr != nil {
			requestError = fmt.Errorf("error closing client response body: %s", respBodyCloseErr.Error())
			success = false
		}
	}()

	// Check status code
	if d.MatchCode && resp.StatusCode != int(d.Code) {
		requestError = fmt.Errorf("received bad status code: %d", resp.StatusCode)
		return
	}

	// Check body content
	if d.MatchContent {
		// Read response body
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			requestError = fmt.Errorf("received error when reading response body: %w", err)
			return
		}

		// Check if body matches regex
		regex, err := regexp.Compile(d.ContentRegex)
		if err != nil {
			requestError = fmt.Errorf("error compiling regex string: %w", err)
			return
		}
		if !regex.Match(body) {
			requestError = fmt.Errorf("received bad response body")
			return
		}
	}

	success = true
	return
}

// Validats the http definition is valid
func (d Definition) Validate() (passed bool, message string) {
	if d.Host == "" {
		return false, "Host needs to be defined"
	}

	if d.Redirect && d.Port != 0 {
		return false, "Port unused due to redirect specified"
	}

	if d.MatchContent && d.ContentRegex != "" {
		if _, err := regexp.Compile(d.ContentRegex); err != nil {
			return false, "Failed to compile regex"
		}
	}

	return true, ""
}
