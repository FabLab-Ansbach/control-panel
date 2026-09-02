package main

import (
	"fmt"
	"os"

	controlcmd "github.com/FabLab-Ansbach/control-panel/cmd/controlctl/cmd"
)

func main() {
	if err := controlcmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
