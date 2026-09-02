package cmd

import (
	"io"
	"log/slog"
	"os"

	"github.com/FabLab-Ansbach/control-panel/internal/config"
	"github.com/spf13/cobra"
)

var cfg *config.Config

var rootCmd = &cobra.Command{
	Use:   "controlctl",
	Short: "Control Panel CLI",
	Long:  `A command-line interface for managing the Control Panel application.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return cmd.Help()
	},
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		verbose, _ := cmd.Flags().GetCount("verbose")
		if verbose >= 2 {
			setDefaultLogger(os.Stderr, slog.LevelDebug)
		} else if verbose == 1 {
			setDefaultLogger(os.Stderr, slog.LevelInfo)
		} else {
			setDefaultLogger(os.Stderr, slog.LevelError)
		}

		configPath, err := cmd.Flags().GetString("config")
		if err != nil {
			return err
		}
		cfg, err = config.LoadConfig(configPath)
		return err
	},
}

func init() {
	rootCmd.SetOut(os.Stdout)
	rootCmd.SetErr(os.Stderr)
	rootCmd.PersistentFlags().StringP("config", "c", "./config.yaml", "path to config file")
	rootCmd.PersistentFlags().CountP("verbose", "v", "increase verbosity (-v, -vv)")
}

func Execute() error {
	return rootCmd.Execute()
}

func setDefaultLogger(w io.Writer, level slog.Level) {
	logger := slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)
}
