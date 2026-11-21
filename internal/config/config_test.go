package config

import (
	"errors"
	"testing"
	"time"

	"proxide/internal/model"
)

func TestDefaultConfigValid(t *testing.T) {
	t.Parallel()
	cfg := Default()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected default config to be valid, got: %v", err)
	}
}

func TestValidateRejectsExcessiveLeafTTL(t *testing.T) {
	t.Parallel()
	cfg := Default()
	cfg.LeafCertTTL = MaxAppleLeafCertTTL + time.Hour
	err := cfg.Validate()
	if !errors.Is(err, model.ErrInvalidLeafTTL) {
		t.Fatalf("expected ErrInvalidLeafTTL, got: %v", err)
	}
}

func TestValidateRejectsNonLoopbackAPIWithoutAuth(t *testing.T) {
	t.Parallel()
	cfg := Default()
	cfg.APIAddr = "0.0.0.0:9090"
	err := cfg.Validate()
	if !errors.Is(err, model.ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig for unauthenticated remote API, got: %v", err)
	}

	cfg.AllowRemoteAPI = true
	cfg.APIToken = "dev-secret-token"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected authenticated remote API to pass validation, got: %v", err)
	}
}

func TestLoadFromFlagsAndEnv(t *testing.T) {
	t.Parallel()
	env := map[string]string{
		"PROXIDE_LISTEN":      "127.0.0.1:8888",
		"PROXIDE_PASSTHROUGH": "roku.com, *.pinned.example",
	}
	cfg, err := LoadFromFlags([]string{"--debug", "--ca-alg", CAAlgorithmRSA2048}, func(k string) string {
		return env[k]
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ProxyAddr != "127.0.0.1:8888" {
		t.Fatalf("unexpected ProxyAddr: %s", cfg.ProxyAddr)
	}
	if cfg.CAAlgorithm != CAAlgorithmRSA2048 {
		t.Fatalf("unexpected CAAlgorithm: %s", cfg.CAAlgorithm)
	}
	if !cfg.Debug {
		t.Fatal("expected Debug to be true")
	}
	if len(cfg.PassthroughHosts) != 2 {
		t.Fatalf("expected 2 passthrough hosts, got %v", cfg.PassthroughHosts)
	}
}
