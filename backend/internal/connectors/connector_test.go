package connectors

import (
	"testing"

	"github.com/FabLab-Ansbach/control-panel/internal/config"
)

type fakeConnectorDefinition struct {
	name string
	typ  string
}

func (f *fakeConnectorDefinition) ConnectorType() string {
	return f.typ
}

func (f *fakeConnectorDefinition) SetName(name string) {
	f.name = name
}

func TestGetConnectors(t *testing.T) {
	t.Run("builds opnsense connector", func(t *testing.T) {
		resolved, err := GetConnectors(config.ConnectorsConfig{
			"main": &config.OPNSenseConnectorCfg{
				Name:      "main",
				Type:      config.ConnectorTypeOPNSense,
				BaseURL:   "https://opnsense.example.com",
				APIKey:    "key",
				APISecret: "secret",
			},
		})
		if err != nil {
			t.Fatalf("GetConnectors returned error: %v", err)
		}

		connector, ok := resolved["main"]
		if !ok {
			t.Fatal("expected connector main to be present")
		}

		if connector.Name() != "main" {
			t.Fatalf("unexpected connector name: %q", connector.Name())
		}
	})

	t.Run("rejects unknown connector types", func(t *testing.T) {
		_, err := GetConnectors(config.ConnectorsConfig{
			"main": &fakeConnectorDefinition{typ: "dns"},
		})
		if err == nil {
			t.Fatal("expected error for unknown connector type, got nil")
		}
	})
}
