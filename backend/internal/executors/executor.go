package executors

import (
	"context"
	"fmt"

	"github.com/FabLab-Ansbach/control-panel/internal/config"
	"github.com/FabLab-Ansbach/control-panel/internal/connectors"
)

type Executor interface {
	// Execute runs the executor and returns the resulting state.
	Execute(ctx context.Context) (bool, error)
	Status(ctx context.Context) (bool, error)
	Name() string
	Connector() connectors.Connector
}

type Factory func(config.ExecutorDefinition, connectors.Set) (Executor, error)

var factories = map[string]Factory{
	config.ExecutorTypeOPNSenseAliasToggle: newOPNSenseAliasToggler,
}

func GetExecutors(cfg config.Config) ([]Executor, error) {
	availableConnectors, err := connectors.GetConnectors(cfg.Connectors)
	if err != nil {
		return nil, err
	}

	var executors []Executor
	for executorName, executorCfg := range cfg.Executors {
		factory, ok := factories[executorCfg.ExecutorType()]
		if !ok {
			return nil, fmt.Errorf("executor type %s not found for executor %s", executorCfg.ExecutorType(), executorName)
		}
		executor, err := factory(executorCfg, availableConnectors)
		if err != nil {
			return nil, fmt.Errorf("failed to create executor %s: %w", executorName, err)
		}
		executors = append(executors, executor)
	}
	return executors, nil
}

func newOPNSenseAliasToggler(definition config.ExecutorDefinition, availableConnectors connectors.Set) (Executor, error) {
	executorCfg, ok := definition.(*config.OPNSenseAliasToggleExecutorCfg)
	if !ok {
		return nil, fmt.Errorf("expected *config.OPNSenseAliasToggleExecutorCfg, got %T", definition)
	}

	connector, ok := availableConnectors[executorCfg.ConnectorName]
	if !ok {
		return nil, fmt.Errorf("connector %s not found for executor %s", executorCfg.ConnectorName, executorCfg.Name)
	}

	opnsenseConnector, ok := connector.(*connectors.OPNSenseBaseConnector)
	if !ok {
		return nil, fmt.Errorf("connector %s has incompatible type %T for executor %s", executorCfg.ConnectorName, connector, executorCfg.Name)
	}

	toggler := NewOPNSenseAliasToggler(executorCfg.Name, opnsenseConnector, executorCfg.AliasName, executorCfg.ToggleValues)
	return toggler, nil
}
