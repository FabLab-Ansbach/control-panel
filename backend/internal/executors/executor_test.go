package executors

import (
	"testing"

	"github.com/FabLab-Ansbach/control-panel/internal/config"
)

type fakeExecutorDefinition struct {
	name string
	typ  string
}

func (f *fakeExecutorDefinition) ExecutorType() string {
	return f.typ
}

func (f *fakeExecutorDefinition) SetName(name string) {
	f.name = name
}

func (f *fakeExecutorDefinition) GetConnectorName() string {
	return ""
}

func TestGetExecutors(t *testing.T) {
	t.Run("builds opnsense alias toggler", func(t *testing.T) {
		cfg := config.Config{
			Connectors: config.ConnectorsConfig{
				"main": &config.OPNSenseConnectorCfg{
					Name:      "main",
					Type:      config.ConnectorTypeOPNSense,
					BaseURL:   "https://opnsense.example.com",
					APIKey:    "key",
					APISecret: "secret",
				},
			},
			Executors: config.ExecutorConfig{
				"toggle1": &config.OPNSenseAliasToggleExecutorCfg{
					Name:          "toggle1",
					Type:          config.ExecutorTypeOPNSenseAliasToggle,
					ConnectorName: "main",
					AliasName:     "test-alias",
					ToggleValue:   "enable",
				},
			},
		}

		resolved, err := GetExecutors(cfg)
		if err != nil {
			t.Fatalf("GetExecutors returned error: %v", err)
		}

		if len(resolved) != 1 {
			t.Fatalf("unexpected executor count: %d", len(resolved))
		}

		toggler, ok := resolved[0].(*OPNSenseAliasToggler)
		if !ok {
			t.Fatalf("unexpected executor type: %T", resolved[0])
		}

		if toggler.Name() != "toggle1" {
			t.Fatalf("unexpected executor name: %q", toggler.Name())
		}
	})

	t.Run("rejects missing referenced connector", func(t *testing.T) {
		cfg := config.Config{
			Executors: config.ExecutorConfig{
				"toggle1": &config.OPNSenseAliasToggleExecutorCfg{
					Name:          "toggle1",
					Type:          config.ExecutorTypeOPNSenseAliasToggle,
					ConnectorName: "main",
					AliasName:     "test-alias",
					ToggleValue:   "enable",
				},
			},
		}

		_, err := GetExecutors(cfg)
		if err == nil {
			t.Fatal("expected error for missing connector, got nil")
		}
	})

	t.Run("rejects unknown executor types", func(t *testing.T) {
		cfg := config.Config{
			Executors: config.ExecutorConfig{
				"toggle1": &fakeExecutorDefinition{typ: "dnsToggleRecord"},
			},
		}

		_, err := GetExecutors(cfg)
		if err == nil {
			t.Fatal("expected error for unknown executor type, got nil")
		}
	})
}
