package smtp_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/andrew-aiken/checks"
	"github.com/andrew-aiken/checks/smtp"
)

func TestMySQL(t *testing.T) {
	var port uint16 = 1025
	host := "127.0.0.1"

	staticConfig := checks.StaticConf{}

	username := "root"
	password := "rootPassword"

	defConf := smtp.Definition{
		Host:      host,
		Port:      port,
		Username:  username,
		Password:  password,
		Body:      "Hello World",
		Sender:    "sender@example.com",
		Recipient: "receiver@example.com",
	}

	ctx := context.Background()
	timeoutContext, cxtCancel := context.WithTimeout(ctx, 3*time.Second)
	defer cxtCancel()

	result := defConf.Run(timeoutContext, staticConfig)

	fmt.Println(result.Passed)
	fmt.Println(result.Message)

	// if result.Passed != tt.Result.Passed {
	// 	t.Fatalf("Check result does not match expected result(%q) message %t", tt.Name, result.Passed)
	// }

	// if tt.MessageSubstring != "" && !strings.Contains(result.Message, tt.MessageSubstring) {
	// 	t.Fatalf("Expected message substring %q for check(%q), got message %q", tt.MessageSubstring, tt.Name, result.Message)
	// }
}
