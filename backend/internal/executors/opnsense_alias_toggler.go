package executors

import (
	"context"

	"github.com/FabLab-Ansbach/control-panel/internal/connectors"
)

type OPNSenseAliasToggler struct {
	TogglerName string
	conn        *connectors.OPNSenseBaseConnector
	AliasName   string
	ToggleValue string
}

func (t *OPNSenseAliasToggler) Name() string {
	return t.TogglerName
}

func (t *OPNSenseAliasToggler) Connector() connectors.Connector {
	return t.conn
}

func NewOPNSenseAliasToggler(togglerName string, connector *connectors.OPNSenseBaseConnector, aliasName, toggleValue string) *OPNSenseAliasToggler {
	return &OPNSenseAliasToggler{
		TogglerName: togglerName,
		conn:        connector,
		AliasName:   aliasName,
		ToggleValue: toggleValue,
	}
}

// Execute toggles ToggleValue in the alias and returns the resulting state
// (true if the value ends up present, false if removed).
func (t *OPNSenseAliasToggler) Execute(ctx context.Context) (bool, error) {
	state, err := t.Status(ctx)
	if err != nil {
		return false, err
	}
	if state {
		if err := t.conn.RemoveValueFromAlias(ctx, t.AliasName, t.ToggleValue); err != nil {
			return false, err
		}
		return false, nil
	}
	if err := t.conn.AddValueToAlias(ctx, t.AliasName, t.ToggleValue); err != nil {
		return false, err
	}
	return true, nil
}

// Status reports whether ToggleValue is currently present in the alias.
func (t *OPNSenseAliasToggler) Status(ctx context.Context) (bool, error) {
	return t.conn.IsValueInAlias(ctx, t.AliasName, t.ToggleValue)
}
