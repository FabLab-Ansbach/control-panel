package main

import (
	"context"
	"log/slog"
	"sync"

	"github.com/FabLab-Ansbach/control-panel/internal/config"
	"github.com/FabLab-Ansbach/control-panel/internal/connectors"
	"github.com/FabLab-Ansbach/control-panel/internal/executors"
	"github.com/FabLab-Ansbach/control-panel/internal/handlers"
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

	conns, err := connectors.GetConnectors(cfg.Connectors)
	if err != nil {
		return err
	}
	slog.InfoContext(ctx, "Initialized connectors", "count", len(conns))

	execs, err := executors.GetExecutors(*cfg)
	if err != nil {
		return err
	}
	slog.InfoContext(ctx, "Initialized executors", "count", len(execs))

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		slog.InfoContext(ctx, "Starting API Server")
		if err := handlers.StartAPIServer(*cfg, execs, conns); err != nil {
			slog.ErrorContext(ctx, "Error starting API server", "err", err)
		}
	}()

	wg.Wait()
	return nil
}
