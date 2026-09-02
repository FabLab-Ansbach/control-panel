package connectors

import (
	"fmt"

	"github.com/FabLab-Ansbach/control-panel/internal/config"
)

type Connector interface {
	Name() string
	ConnectorType() string
}

type Set map[string]Connector

type Factory func(config.ConnectorDefinition) (Connector, error)

var factories = map[string]Factory{
	config.ConnectorTypeOPNSense: newOPNSenseBaseConnector,
}

func GetConnectors(cfg config.ConnectorsConfig) (Set, error) {
	resolved := make(Set, len(cfg))
	for name, definition := range cfg {
		factory, ok := factories[definition.ConnectorType()]
		if !ok {
			return nil, fmt.Errorf("connector type %q not found for connector %q", definition.ConnectorType(), name)
		}

		connector, err := factory(definition)
		if err != nil {
			return nil, fmt.Errorf("create connector %q: %w", name, err)
		}

		resolved[name] = connector
	}

	return resolved, nil
}

func newOPNSenseBaseConnector(definition config.ConnectorDefinition) (Connector, error) {
	opnsenseCfg, ok := definition.(*config.OPNSenseConnectorCfg)
	if !ok {
		return nil, fmt.Errorf("expected *config.OPNSenseConnectorCfg, got %T", definition)
	}

	return NewOPNSenseBaseConnector(*opnsenseCfg), nil
}
