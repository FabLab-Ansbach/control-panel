package executors

import (
	"context"

	"github.com/FabLab-Ansbach/control-panel/internal/connectors"
)

// OPNSenseAliasToggler toggles a set of values (host IPs and/or CIDR
// networks - OPNsense's alias content treats both as plain address
// entries) in and out of an alias together, as one unit.
type OPNSenseAliasToggler struct {
	TogglerName  string
	conn         *connectors.OPNSenseBaseConnector
	AliasName    string
	ToggleValues []string
}

func (t *OPNSenseAliasToggler) Name() string {
	return t.TogglerName
}

func (t *OPNSenseAliasToggler) Connector() connectors.Connector {
	return t.conn
}

func NewOPNSenseAliasToggler(togglerName string, connector *connectors.OPNSenseBaseConnector, aliasName string, toggleValues []string) *OPNSenseAliasToggler {
	return &OPNSenseAliasToggler{
		TogglerName:  togglerName,
		conn:         connector,
		AliasName:    aliasName,
		ToggleValues: toggleValues,
	}
}

// Execute toggles ToggleValues in the alias and returns the resulting state
// (true if the values end up present, false if removed). The alias'
// content is replaced wholesale in one request, based on the current state
// reported by Status - this alias is assumed to be owned exclusively by
// this toggler, so it's safe to set its content to either "all of
// ToggleValues" or "empty".
func (t *OPNSenseAliasToggler) Execute(ctx context.Context) (bool, error) {
	state, err := t.Status(ctx)
	if err != nil {
		return false, err
	}
	if state {
		if err := t.conn.SetAliasContent(ctx, t.AliasName, nil); err != nil {
			return false, err
		}
		return false, nil
	}
	if err := t.conn.SetAliasContent(ctx, t.AliasName, t.ToggleValues); err != nil {
		return false, err
	}
	return true, nil
}

// Status reports whether all ToggleValues are currently present in the
// alias, checked with a single list request.
func (t *OPNSenseAliasToggler) Status(ctx context.Context) (bool, error) {
	return t.conn.ValuesInAlias(ctx, t.AliasName, t.ToggleValues)
}
