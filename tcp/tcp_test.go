package tcp_test

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/andrew-aiken/checks"
	"github.com/andrew-aiken/checks/tcp"
)

var tcpServerOutput string = "ServerOutput"

func TestTCPValidate(t *testing.T) {
	tests := []struct {
		Name            string
		Definition      tcp.Definition
		ValidateMessage string
	}{
		{
			Name: "Valid",
			Definition: tcp.Definition{
				Host: "tcp.neccdl.org",
				Port: 1337,
			},
		},
		{
			Name: "MissingHost",
			Definition: tcp.Definition{
				// Host:     "tcp.neccdl.org",
				Port: 1337,
			},
			ValidateMessage: "Host needs to be defined",
		},
		{
			Name: "MissingPort",
			Definition: tcp.Definition{
				Host: "tcp.neccdl.org",
				// Port: 1337,
			},
			ValidateMessage: "Port needs to be defined",
		},
		{
			Name: "InvalidRegex",
			Definition: tcp.Definition{
				Host:         "ftp.neccdl.org",
				Port:         1337,
				ContentRegex: "[a-z",
				MatchContent: true,
			},
			ValidateMessage: "Failed to compile regex",
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			_, message := tt.Definition.Validate()
			if message != tt.ValidateMessage {
				t.Fatalf("Validate message does not match expected message(%q): got %q want %q", tt.Name, message, tt.ValidateMessage)
			}
		})
	}
}

func TestTCPCheck(t *testing.T) {
	staticConfig := checks.StaticConf{}

	host := "127.0.0.1"
	var port uint16 = 8090

	go tcpServer(host, port, "read")

	tests := []struct {
		Name             string
		Definition       tcp.Definition
		Result           checks.Results
		MessageSubstring string
	}{
		{
			Name: "Valid",
			Definition: tcp.Definition{
				Host:         host,
				Port:         port,
				MatchContent: true,
				ContentRegex: tcpServerOutput,
			},
			Result: checks.Results{
				Passed: true,
			},
		},
		{
			Name: "FailureTemplateParse",
			Definition: tcp.Definition{
				Host: "{{",
				Port: port,
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "internal error templating definition",
		},
		{
			Name: "Timeout",
			Definition: tcp.Definition{
				Host: host,
				Port: port + 1,
				SharedDefinition: checks.SharedDefinition{
					Timeout: 3,
				},
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Failed to connect: dial tcp 127.0.0.1:8091: connect: connection refused",
		},
		{
			Name: "FailedRegexMatch",
			Definition: tcp.Definition{
				Host:         host,
				Port:         port,
				MatchContent: true,
				ContentRegex: "DNE",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "File contents does not match regex",
		},
		{
			Name: "InvalidRegex",
			Definition: tcp.Definition{
				Host:         host,
				Port:         port,
				MatchContent: true,
				ContentRegex: "[a-z",
			},
			Result: checks.Results{
				Passed: false,
			},
			MessageSubstring: "Error compiling regex string",
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			ctx := context.Background()
			timeoutContext, cxtCancel := context.WithTimeout(ctx, 5*time.Second)
			defer cxtCancel()

			result := tt.Definition.Run(timeoutContext, staticConfig)

			if result.Passed != tt.Result.Passed {
				t.Fatalf("Check result does not match expected result(%q) message %t", tt.Name, result.Passed)
			}

			if tt.MessageSubstring != "" && !strings.Contains(result.Message, tt.MessageSubstring) {
				t.Fatalf("Expected message substring %q for check(%q), got message %q", tt.MessageSubstring, tt.Name, result.Message)
			}
		})
	}
}

func TestTCPCheckWrite(t *testing.T) {
	staticConfig := checks.StaticConf{}

	host := "127.0.0.1"
	var port uint16 = 8091

	go tcpServer(host, port, "write")

	time.Sleep(500 * time.Millisecond)

	tests := []struct {
		Name             string
		Definition       tcp.Definition
		Result           checks.Results
		MessageSubstring string
	}{
		{
			Name: "Valid",
			Definition: tcp.Definition{
				Host:  host,
				Port:  port,
				Write: "WriteTCP",
			},
			Result: checks.Results{
				Passed: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			ctx := context.Background()
			timeoutContext, cxtCancel := context.WithTimeout(ctx, 5*time.Second)
			defer cxtCancel()

			result := tt.Definition.Run(timeoutContext, staticConfig)

			if result.Passed != tt.Result.Passed {
				t.Fatalf("Check result does not match expected result(%q) message %t", tt.Name, result.Passed)
			}

			if tt.MessageSubstring != "" && !strings.Contains(result.Message, tt.MessageSubstring) {
				t.Fatalf("Expected message substring %q for check(%q), got message %q", tt.MessageSubstring, tt.Name, result.Message)
			}
		})
	}
}

func tcpServer(host string, port uint16, mode string) {
	address := fmt.Sprintf("%s:%d", host, port)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		fmt.Printf("Failed to start TCP listener: %s\n", err)
		return
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Printf("Failed accepting connection: %s\n", err)
			return
		}
		switch mode {
		case "write":
			scanner := bufio.NewScanner(conn)

			if scanner.Scan() {
				message := scanner.Text()
				fmt.Println(message)
			}
		case "read":
			conn.Write([]byte(tcpServerOutput))
		default:
			fmt.Println("Unknown tcp server mode")
			return
		}
	}
}
