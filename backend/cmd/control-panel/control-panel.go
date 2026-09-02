package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/FabLab-Ansbach/control-panel/internal/authn"
	"github.com/FabLab-Ansbach/control-panel/internal/config"
	"github.com/FabLab-Ansbach/control-panel/internal/connectors"
	"github.com/FabLab-Ansbach/control-panel/internal/executors"
	"github.com/FabLab-Ansbach/control-panel/internal/handlers"
	"github.com/FabLab-Ansbach/control-panel/internal/reqlog"
)

func main() {
	slog.SetDefault(slog.New(reqlog.Handler{Handler: slog.NewTextHandler(os.Stderr, nil)}))
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

	if cfg.AuthConfig == nil {
		return errors.New("authConfig is required")
	}
	slog.InfoContext(ctx, "Discovering OIDC provider", "issuer", cfg.AuthConfig.IssuerURL)
	discoverCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	auth, err := authn.New(discoverCtx, *cfg.AuthConfig)
	cancel()
	if err != nil {
		return fmt.Errorf("discover OIDC provider at %q: %w", cfg.AuthConfig.IssuerURL, err)
	}
	slog.InfoContext(ctx, "Initialized OIDC authenticator", "issuer", cfg.AuthConfig.IssuerURL)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		slog.InfoContext(ctx, "Starting API Server")
		if err := handlers.StartAPIServer(*cfg, execs, conns, auth); err != nil {
			slog.ErrorContext(ctx, "Error starting API server", "err", err)
		}
	}()

	wg.Wait()
	return nil
}
