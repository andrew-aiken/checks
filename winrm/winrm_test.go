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
	timeoutContext, cxtCancel := context.WithTimeout(ctx, 3*time.Second)
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
	}

	results := config.Run(timeoutContext, staticConf)

	fmt.Println(results.Passed)
	fmt.Println(results.Message)

	// errChan := make(chan error, 1)

	// go func() {
	// 	defer close(errChan)
	// 	endpoint := winrm.NewEndpoint(host, 5985, false, false, nil, nil, nil, 10*time.Second)

	// 	params := winrm.DefaultParameters
	// 	params.TransportDecorator = func() winrm.Transporter {
	// 		encryption, err := winrm.NewEncryption("ntlm")
	// 		if err != nil {
	// 			panic(err)
	// 		}
	// 		return encryption
	// 	}

	// 	client, err := winrm.NewClientWithParameters(endpoint, "Administrator", "(icos0xw1))A6p%Hvn%Vls$.IZKZJMu4", params)
	// 	if err != nil {
	// 		errChan <- fmt.Errorf("failed to create client: %v", err)
	// 		return
	// 	}

	// 	stdout, stderr, _, err := client.RunCmdWithContext(timeoutContext, "ipconfig")
	// 	if err != nil {
	// 		errChan <- fmt.Errorf("failed to run command: %v", err)
	// 		return
	// 	}

	// 	fmt.Println(stdout)

	// 	if stderr != "" {
	// 		errChan <- fmt.Errorf("command returned error: %s", stderr)
	// 		return
	// 	}

	// 	// if strings.TrimSpace(stdout) != strings.TrimSpace(conf.ExpectedOutput) {
	// 	// 	errChan <- fmt.Errorf("expected output does not match actual output: %q != %q", conf.ExpectedOutput, stdout)
	// 	// 	return
	// 	// }

	// 	errChan <- nil
	// }()

	// select {
	// case <-ctx.Done():
	// 	fmt.Println(timeoutContext.Err())
	// 	return
	// case err := <-errChan:
	// 	fmt.Println(err)
	// 	return
	// }

}
