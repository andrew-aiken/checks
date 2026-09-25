package redis

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"slices"
	"strconv"
	"time"

	"github.com/andrew-aiken/checks"

	"github.com/redis/go-redis/v9"
)

type Definition struct {
	// IP or FQDN of the redis server
	Host string `json:"host" optiontype:"required"`
	// TCP port number the server is listening on
	Port uint16 `json:"port" default:"6379"`
	// User that connects to redis
	Username string `json:"username"`
	// The users password
	Password string `json:"password"`
	// Database to connect to
	Database uint `json:"database" default:"0"`
	// Connect with TLS
	TLS bool `json:"tls" default:"false"`
	// Whether to skip verification of the server's TLS certificate
	TLSSkipVerify bool `json:"tlsSkipVerify" default:"false"`
	// Redis command
	// Options: GET, SET, INCR
	Command string `json:"command"`
	// Redis key the command targets
	Key string `json:"key"`
	// Value to set when command is SET
	Value string `json:"value"`
	// Whether the file must match a defined regex for the check to pass
	MatchContent bool `json:"matchContent" default:"false"`
	// Regex to match against the returned file
	ContentRegex string `json:"contentRegex" default:".*"`
	// Shared configuration across all checks
	checks.SharedDefinition
}

// Run performs a Redis check
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

	portString := strconv.Itoa(int(definition.Port))
	address := net.JoinHostPort(definition.Host, portString)

	config := redis.Options{
		Addr:        address,
		Username:    definition.Username,
		Password:    definition.Password,
		DB:          int(definition.Database),
		MaxRetries:  3,
		DialTimeout: time.Duration(definition.Timeout),
	}

	if definition.TLS {
		config.TLSConfig = &tls.Config{
			ServerName:         definition.Host,
			InsecureSkipVerify: definition.TLSSkipVerify, // #nosec G402
		}
	}

	rdb := redis.NewClient(&config)
	defer func() {
		clientCloseErr := rdb.Close()
		if err == nil && clientCloseErr != nil {
			result.Message = fmt.Sprintf("error closing redis client: %s", clientCloseErr.Error())
			result.Passed = false
		}
	}()

	conn := rdb.Conn()
	defer func() {
		connCloseErr := conn.Close()
		if err == nil && connCloseErr != nil {
			result.Message = fmt.Sprintf("error closing redis connection: %s", connCloseErr.Error())
			result.Passed = false
		}
	}()

	_, err = conn.Ping(ctx).Result()
	if err != nil {
		result.Message = fmt.Sprintf("Error while pinging querying: %s", err.Error())
		return
	}

	switch definition.Command {
	case "SET":
		setResp := conn.Set(ctx, definition.Key, definition.Value, time.Duration(24*time.Hour))
		if setResp.Err() != nil {
			result.Message = fmt.Sprintf("Error while setting key: %s", err.Error())
			return
		}
	case "GET":
		value, err := conn.Get(ctx, definition.Key).Result()
		if err == redis.Nil {
			result.Message = fmt.Sprintf("Error key does not exist: %s", err.Error())
			return
		}
		if err != nil {
			result.Message = fmt.Sprintf("Error while getting key: %s", err.Error())
			return
		}

		if definition.MatchContent {
			regex, err := regexp.Compile(definition.ContentRegex)
			if err != nil {
				result.Message = fmt.Sprintf("Error compiling regex string: %s", err)
				return
			}
			if !regex.Match([]byte(value)) {
				result.Message = "Value does not match regex"
				return
			}
		}
	case "INCR":
		_, err := conn.Incr(ctx, definition.Key).Result()
		if err != nil {
			result.Message = fmt.Sprintf("Error while incrementing key: %s", err.Error())
			return
		}
	case "":
	default:
		result.Passed = true
		return
	}

	result.Passed = true
	return
}

// Validate checks if the Redis definition is valid
func (d Definition) Validate() (passed bool, message string) {
	if d.Host == "" {
		return false, "Host needs to be defined"
	}

	items := []string{"", "GET", "SET", "INCR"}
	if !slices.Contains(items, d.Command) {
		return false, "Invalid command option"
	}

	if d.Command != "" {
		if d.Key == "" {
			return false, "Key must be defined"
		}

		if d.Command == "SET" && d.Value == "" {
			return false, "Value must be defined when using the 'SET' command"
		}
	}

	if d.MatchContent && d.ContentRegex != "" {
		if _, err := regexp.Compile(d.ContentRegex); err != nil {
			return false, "Failed to compile regex"
		}
	}

	return true, ""
}
