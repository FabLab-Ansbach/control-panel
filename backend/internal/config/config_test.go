package config

import (
	"strings"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	t.Run("loads valid config", func(t *testing.T) {
		cfg, err := LoadConfig("testdata/valid.yaml")
		if err != nil {
			t.Fatalf("LoadConfig returned error: %v", err)
		}

		if cfg.BaseURL != "https://example.com" {
			t.Fatalf("unexpected BaseURL: %q", cfg.BaseURL)
		}

		if cfg.SecretKey != "super-secret" {
			t.Fatalf("unexpected SecretKey: %q", cfg.SecretKey)
		}

		connector, ok := cfg.Connectors["firewall"]
		if !ok {
			t.Fatal("expected opnsense connector firewall to be present")
		}

		conn, ok := connector.(*OPNSenseConnectorCfg)
		if !ok {
			t.Fatalf("unexpected connector type: %T", connector)
		}

		if conn.BaseURL != "https://opnsense.example.com" {
			t.Fatalf("unexpected connector BaseURL: %q", conn.BaseURL)
		}

		if conn.Name != "firewall" {
			t.Fatalf("unexpected connector name: %q", conn.Name)
		}

		if conn.Type != ConnectorTypeOPNSense {
			t.Fatalf("unexpected connector type discriminator: %q", conn.Type)
		}

		executor, ok := cfg.Executors["restrict-inet"]
		if !ok {
			t.Fatal("expected executor restrict-inet to be present")
		}

		toggle, ok := executor.(*OPNSenseAliasToggleExecutorCfg)
		if !ok {
			t.Fatalf("unexpected executor type: %T", executor)
		}

		if toggle.Name != "restrict-inet" {
			t.Fatalf("unexpected executor name: %q", toggle.Name)
		}

		if toggle.Type != "opnsenseAliasToggle" {
			t.Fatalf("unexpected executor type discriminator: %q", toggle.Type)
		}
	})

	t.Run("rejects unknown fields", func(t *testing.T) {
		_, err := LoadConfig("testdata/bad-connector-unknown-field.yaml")
		if err == nil {
			t.Fatal("expected error for unknown field, got nil")
		}

		if !strings.Contains(err.Error(), "field extraField not found") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("allows missing top-level secretKey", func(t *testing.T) {
		cfg, err := LoadConfig("testdata/no-secret-key.yaml")
		if err != nil {
			t.Fatalf("LoadConfig returned error: %v", err)
		}

		if cfg.SecretKey != "" {
			t.Fatalf("unexpected SecretKey: %q", cfg.SecretKey)
		}
	})

	t.Run("rejects missing nested required fields", func(t *testing.T) {
		_, err := LoadConfig("testdata/bad-connector-missing-required-field.yaml")
		if err == nil {
			t.Fatal("expected error for missing nested required field, got nil")
		}

		if !strings.Contains(err.Error(), "required config field \"APISecret\" is missing") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("rejects connector unknown type", func(t *testing.T) {
		_, err := LoadConfig("testdata/bad-connector-unknown-type.yaml")
		if err == nil {
			t.Fatal("expected error for connector unknown type, got nil")
		}

		if !strings.Contains(err.Error(), "unknown type \"dns\"") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("rejects executor unknown fields", func(t *testing.T) {
		_, err := LoadConfig("testdata/bad-executor-unknown-field.yaml")
		if err == nil {
			t.Fatal("expected error for executor unknown field, got nil")
		}

		if !strings.Contains(err.Error(), "field toggleValua not found") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("rejects executor unknown type", func(t *testing.T) {
		_, err := LoadConfig("testdata/bad-executor-unknown-type.yaml")
		if err == nil {
			t.Fatal("expected error for executor unknown type, got nil")
		}

		if !strings.Contains(err.Error(), "unknown type \"dnsToggleRecord\"") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}
