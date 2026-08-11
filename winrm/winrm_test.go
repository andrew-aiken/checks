package winrm_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/andrew-aiken/checks"
	"github.com/andrew-aiken/checks/winrm"
)

func TestWinrm(t *testing.T) {
	// if os.Getenv("CI_WINRM") == "" {
	// 	t.Skip("WINRM server test flag missing")
	// }

	host := "54.174.178.120"

	ctx := context.Background()
	timeoutContext, cxtCancel := context.WithTimeout(ctx, 10*time.Second)
	defer cxtCancel()

	var staticConf = checks.StaticConf{}

	config := winrm.Definition{
		Host:     host,
		Port:     5985,
		Command:  "whoami",
		MatchContent: true,
		// Username: "Administrator",
		// Password: "M09@QKqKhIjFMXxKHG1M!NvamNST4*T7",
		// TransportProtocol: "ntlm",
		// ContentRegex: `ec2amaz-sf7nb60\\administrator.*`,
		Username: "johndoe",
		Password: "XHM5pwf-hbz0bzw-hnh2",
		ContentRegex: `corp\\johndoe.*`,
		TransportProtocol: "kerberos",
		Realm: "CORP.EXAMPLE.ORG",
		Hostname: "EC2AMAZ-SF7NB60",
		Encrypted: false,
	}

	results := config.Run(timeoutContext, staticConf)

	fmt.Println(results.Message)
	if !results.Passed {
		t.FailNow()
	}
}
