package mysql

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/andrew-aiken/checks"

	_ "github.com/go-sql-driver/mysql"
)

type Definition struct {
	// IP or FQDN of the database server
	Host string `json:"host" optiontype:"required"`
	// TCP port number the mysql server is listening on
	Port uint16 `json:"port" default:"3306"`
	// User that connects to the mysql database
	Username string `json:"username" optiontype:"required"`
	// The users password
	Password string `json:"password"`
	// Database to connect to
	Database string `json:"database" optiontype:"required"`
	// TLS connection option
	// Valid options are true, false, skip-verify, preferred.
	TLS string `json:"tls" default:"false"`
	// SQL Query to run
	Query string `json:"query"`
	// Whether the file must match a defined regex for the check to pass
	MatchContent bool `json:"matchContent" default:"false"`
	// Regex to match against the returned file
	ContentRegex string `json:"contentRegex" default:".*"`
	// Shared configuration across all checks
	checks.SharedDefinition
}

// Run performs a MySQL check
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

	var databaseParameters string
	if definition.TLS != "" {
		databaseParameters = "?tls=" + definition.TLS
	}

	// Adding custom DSN parameters would be relative simple to implement
	// Would just need to have some checks around formatting
	// https://github.com/go-sql-driver/mysql#parameters
	connectionDSN := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s%s", definition.Username, definition.Password, definition.Host, definition.Port, definition.Database, databaseParameters)
	db, err := sql.Open("mysql", connectionDSN)
	if err != nil {
		// TODO: not sure how to test this
		result.Message = fmt.Sprintf("Failed to create database handle: %s", err)
		return
	}
	defer db.Close()

	db.SetMaxOpenConns(1)
	db.SetConnMaxLifetime(time.Duration(definition.Timeout) * time.Second)
	db.SetConnMaxIdleTime(time.Duration(definition.Timeout) * time.Second)

	// Check db connection
	err = db.PingContext(ctx)
	if err != nil {
		result.Message = fmt.Sprintf("Failed to connect to database: %s", err)
		return
	}

	// If no query is defined pass the check
	if definition.Query == "" {
		result.Passed = true
		return
	}

	rows, err := db.QueryContext(ctx, definition.Query)
	if err != nil {
		result.Message = fmt.Sprintf("Failed to query database: %s", err)
		return
	}
	defer rows.Close()

	if definition.MatchContent {
		regex, err := regexp.Compile(definition.ContentRegex)
		if err != nil {
			result.Message = fmt.Sprintf("Error compiling regex string: %s", err)
			return
		}

		var val string

		for rows.Next() {
			err := rows.Scan(&val)
			if err != nil {
				result.Message = fmt.Sprintf("Could not scan row values: %s", err)
				return
			}
			if err = rows.Err(); err != nil {
				result.Message = fmt.Sprintf("Error while querying row: %s", err)
				return
			}

			if regex.MatchString(val) {
				result.Passed = true
				return
			}
		}

		result.Message = "File contents does not match regex"
		return
	}

	result.Passed = true
	return
}

// Validate checks if the mysql definition is valid
func (d Definition) Validate() (passed bool, message string) {
	if d.Host == "" {
		return false, "Host needs to be defined"
	}

	if d.Username == "" {
		return false, "Username needs to be defined"
	}

	if d.Database == "" {
		return false, "Database needs to be defined"
	}

	// Check if TLS option is valid
	// https://github.com/go-sql-driver/mysql#tls
	items := []string{"", "true", "false", "skip-verify", "preferred"}
	if !slices.Contains(items, d.TLS) {
		return false, "Invalid TLS option"
	}

	if d.MatchContent && d.ContentRegex != "" {
		if _, err := regexp.Compile(d.ContentRegex); err != nil {
			return false, "Failed to compile regex"
		}
	}

	return true, ""
}
