package cmd

import (
	"fmt"
	"sort"
	"text/tabwriter"

	"github.com/FabLab-Ansbach/control-panel/internal/executors"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

var executorCmd = &cobra.Command{
	Use:   "executor executor command",
	Short: "Interact with a configured executor",
	Long:  `Run "status" or "execute" against a configured executor.`,
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		executor, err := findExecutor(args[0])
		if err != nil {
			return err
		}

		switch command := args[1]; command {
		case "status":
			state, err := executor.Status(cmd.Context())
			if err != nil {
				return err
			}
			cmd.Println(state)
			return nil
		case "execute":
			state, err := executor.Execute(cmd.Context())
			if err != nil {
				return err
			}
			cmd.Println(state)
			return nil
		default:
			return errors.Errorf("unknown command %q, expected \"status\" or \"execute\"", command)
		}
	},
}

var executorListCmd = &cobra.Command{
	Use:   "list",
	Short: "List configured executors",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		withState, err := cmd.Flags().GetBool("with-state")
		if err != nil {
			return err
		}

		names := make([]string, 0, len(cfg.Executors))
		for name := range cfg.Executors {
			names = append(names, name)
		}
		sort.Strings(names)

		var live map[string]executors.Executor
		if withState {
			all, err := executors.GetExecutors(*cfg)
			if err != nil {
				return err
			}
			live = make(map[string]executors.Executor, len(all))
			for _, e := range all {
				live[e.Name()] = e
			}
		}

		w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
		header := "NAME\tTYPE\tCONNECTOR"
		if withState {
			header += "\tSTATE"
		}
		fmt.Fprintln(w, header)

		for _, name := range names {
			definition := cfg.Executors[name]
			row := fmt.Sprintf("%s\t%s\t%s", name, definition.ExecutorType(), definition.GetConnectorName())
			if withState {
				state, err := live[name].Status(cmd.Context())
				if err != nil {
					return err
				}
				row += fmt.Sprintf("\t%v", state)
			}
			fmt.Fprintln(w, row)
		}
		return w.Flush()
	},
}

func findExecutor(name string) (executors.Executor, error) {
	all, err := executors.GetExecutors(*cfg)
	if err != nil {
		return nil, err
	}
	for _, e := range all {
		if e.Name() == name {
			return e, nil
		}
	}
	return nil, errors.Errorf("executor not found: %s", name)
}

func init() {
	executorListCmd.Flags().Bool("with-state", false, "also query and print each executor's current state")
	executorCmd.AddCommand(executorListCmd)
	rootCmd.AddCommand(executorCmd)
}
