package cmd

import (
	"context"
	"log/slog"

	"github.com/FabLab-Ansbach/control-panel/internal/config"
	"github.com/FabLab-Ansbach/control-panel/internal/connectors"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

var opnsenseCmd = &cobra.Command{
	Use:   "opnsense",
	Short: "Interact with the OPNsense API",
	Long:  `A command-line interface for interacting with the OPNsense API.`,
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.Help()
		return nil
	},
}

var opnsenseApiCmd = &cobra.Command{
	Use:   "api connection endpoint",
	Short: "Interact with the OPNsense API",
	Long:  `A command-line interface for interacting with the OPNsense API.`,
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		resp, err := opnsenseRun(cmd.Context(), args[0], args[1])
		if err != nil {
			return err
		}
		cmd.Println(resp)
		return nil
	},
}

func opnsenseRun(ctx context.Context, connector, endpoint string) (string, error) {
	connectorCfg, ok := cfg.Connectors[connector]
	if !ok {
		slog.ErrorContext(ctx, "Connector not found.", "connector", connector)
		return "", errors.Errorf("Connector not found: %s", connector)
	}

	opnsenseConnectorCfg, ok := connectorCfg.(*config.OPNSenseConnectorCfg)
	if !ok {
		slog.ErrorContext(ctx, "Connector has wrong type.", "connector", connector, "type", connectorCfg.ConnectorType())
		return "", errors.Errorf("Connector %s is not an opnsense connector", connector)
	}

	opnsenseConnector := connectors.NewOPNSenseBaseConnector(*opnsenseConnectorCfg)

	resp, err := opnsenseConnector.ExecuteGetRequest(ctx, endpoint)
	return resp, err
}

func init() {
	opnsenseCmd.AddCommand(opnsenseApiCmd)
	rootCmd.AddCommand(opnsenseCmd)
}
