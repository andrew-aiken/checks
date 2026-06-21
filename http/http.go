package http

import (
	"context"
	"crypto/tls"
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
	Host         string            `json:"host" optiontype:"required"` // IP or FQDN of the HTTP server
	Path         string            `json:"path" default:"/"`           // Path to request - see RFC3986, section 3.3
	HTTPS        bool              `json:"https" default:"false"`      // if HTTPS is to be used
	Port         uint16            `json:"port" default:"80"`          // TCP port number the HTTP server is listening on
	Method       string            `json:"method" default:"GET"`       // HTTP method to use
	Code         uint16            `json:"code" default:"200"`         // the response status code to match
	ContentRegex string            `json:"contentRegex" default:".*"`  // regex for the response body to match
	Headers      map[string]string `json:"headers"`                    // name-value pairs of header fields to add/override
	Body         string            `json:"body"`                       // the request body
	MatchCode    bool              `json:"matchCode"`                  // whether the response code must match a defined value for the check to pass
	MatchContent bool              `json:"matchContent"`               // whether the response body must match a defined regex for the check to pass
	Redirect     bool              `json:"redirect"`                   // whether to follow http redirects
	VerifyCert   bool              `json:"verifyCert"`                 // whether to verify the server's TLS certificate
	Timeout      uint8             `json:"timeout" default:"20"`       // Timeout for the http query in seconds
}

func (d Definition) Run(ctx context.Context, static checks.StaticConf) checks.Results {
	// Initialize empty result
	result := checks.Results{Timestamp: time.Now()}

	// Configure HTTP client
	cookieJar, err := cookiejar.New(nil)
	if err != nil {
		result.Message = "Could not create CookieJar"
		return result
	}

	var redirect func(req *http.Request, via []*http.Request) error

	// If redirects are not allowed, set the redirect function to prevent following them
	if !d.Redirect {
		redirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	client := &http.Client{
		Jar: cookieJar,
		Transport: &http.Transport{
			IdleConnTimeout: 10 * time.Second,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: !d.VerifyCert,
			},
		},
		CheckRedirect: redirect,
		Timeout:       time.Duration(d.Timeout) * time.Second,
	}

	// TODO: create child context with deadline less than the parent context
	pass, _, err := d.request(ctx, client)

	// Process request results
	result.Passed = pass
	if err != nil {
		result.Message = fmt.Sprintf("%s", err)
	}

	return result
}

func (d Definition) request(ctx context.Context, client *http.Client) (success bool, foo *string, err error) {
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
		return false, nil, fmt.Errorf("Error constructing request: %s", err)
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
		return false, nil, fmt.Errorf("Error making request: %s", err)
	}
	defer resp.Body.Close()

	// Check status code
	if d.MatchCode && uint16(resp.StatusCode) != d.Code {
		return false, nil, fmt.Errorf("Received bad status code: %d", resp.StatusCode)
	}

	// Check body content
	var matchStr string
	if d.MatchContent {
		// Read response body
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return false, nil, fmt.Errorf("Received error when reading response body: %s", err)
		}

		// Check if body matches regex
		regex, err := regexp.Compile(d.ContentRegex)
		if err != nil {
			return false, nil, fmt.Errorf("Error compiling regex string %s : %s", d.ContentRegex, err)
		}
		if !regex.Match(body) {
			return false, nil, fmt.Errorf("Received bad response body")
		}
		matches := regex.FindSubmatch(body)
		matchStr = string(matches[len(matches)-1])
	}

	// If we've reached this point, then the check succeeded
	return true, &matchStr, nil
}

// Validats the http definition is valid
func (d Definition) Validate() (passed bool, message string) {
	if d.Host == "" {
		return false, "Host needs to be defined"
	}

	return true, ""
}
