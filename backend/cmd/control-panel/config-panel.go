package main

import (
	"context"
	"log/slog"

	"github.com/FabLab-Ansbach/control-panel/internal/config"
)

func main() {
	if err := mainFunc(); err != nil {
		panic(err)
	}
}

func mainFunc() error {
	ctx := context.Background()
	slog.InfoContext(ctx, "Starting control panel")
	cfg, err := config.LoadConfig("./config.yaml")
	if err != nil {
		return err
	}
	slog.InfoContext(ctx, "Loaded config", "baseUrl", cfg.BaseURL)
	return nil
}
