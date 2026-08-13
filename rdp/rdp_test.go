package rdp_test

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/andrew-aiken/checks"
	"github.com/andrew-aiken/checks/rdp"
)

func TestRDP(t *testing.T) {
	staticConfig := checks.StaticConf{}

	opts := &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}

	// Create a text or JSON handler
	handler := slog.NewTextHandler(os.Stdout, opts)
	logger := slog.New(handler)

	// Set as the global default logger
	slog.SetDefault(logger)

	tests := []struct {
		Name             string
		Definition       rdp.Definition
		Result           checks.Results
		MessageSubstring string
	}{
		{
			Name: "Valid",
			Definition: rdp.Definition{
				Host:     "3.81.127.110",
				Port:     3389,
				Username: "Administrator",
				Password: "aCPsGZFtrQk$@UruoHF=Xtz.BeB!2kpb",
				Domain:   "",
			},
			Result: checks.Results{
				Passed: false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			ctx := context.Background()
			timeoutContext, cxtCancel := context.WithTimeout(ctx, 30*time.Second)
			defer cxtCancel()

			result := tt.Definition.Run(timeoutContext, staticConfig)

			fmt.Println(result.Passed)
			fmt.Println(result.Message)

			// if result.Passed != tt.Result.Passed {
			// 	t.Fatalf("Check result does not match expected result(%q) message %t", tt.Name, result.Passed)
			// }

			// if tt.MessageSubstring != "" && !strings.Contains(result.Message, tt.MessageSubstring) {
			// 	t.Fatalf("Expected message substring %q for check(%q), got message %q", tt.MessageSubstring, tt.Name, result.Message)
			// }
		})
	}
}
