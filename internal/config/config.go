// Package config turns CLI flags into runtime configuration for the agent.
package config

import (
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Bino97/boarnet-agent/internal/envelope"
	"github.com/Bino97/boarnet-agent/internal/hash"
)

type Config struct {
	SensorID    string
	Fleet       envelope.Fleet
	SSHPort     string
	TLSPort     string
	IngestURL   string
	Token       string // TODO: replace with mTLS
	DataDir     string
	PepperKeyID string
	Pepper      hash.Pepper
}

func Parse(args []string) (*Config, error) {
	fs := flag.NewFlagSet("boarnet", flag.ContinueOnError)

	cfg := &Config{}
	fs.StringVar(&cfg.SensorID, "sensor-id", "dev-local", "registered sensor id")
	fleet := fs.String("fleet", "mesh", "fleet: core | mesh")
	fs.StringVar(&cfg.SSHPort, "ssh-port", "2222", "ssh honeypot listen port")
	fs.StringVar(&cfg.TLSPort, "tls-port", "8443", "tls honeypot listen port")
	fs.StringVar(&cfg.IngestURL, "ingest-url", "http://localhost:3000/v1/events", "ingest service URL")
	fs.StringVar(&cfg.Token, "token", "", "bearer token (TEMPORARY — mTLS supersedes this)")
	fs.StringVar(&cfg.DataDir, "data-dir", ".boarnet", "where to keep buffer, pepper, key")
	fs.StringVar(&cfg.PepperKeyID, "pepper-key-id", "pepper-dev", "HMAC pepper generation id")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	cfg.Fleet = envelope.Fleet(*fleet)
	if cfg.Fleet != envelope.FleetCore && cfg.Fleet != envelope.FleetMesh {
		return nil, fmt.Errorf("invalid fleet %q", *fleet)
	}

	secret, err := loadOrCreatePepper(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	cfg.Pepper = hash.Pepper{KeyID: cfg.PepperKeyID, Secret: secret}

	return cfg, nil
}

// loadOrCreatePepper reads a 32-byte HMAC secret from dataDir/pepper, creating
// one if missing. In production, the pepper is provisioned by the ingest
// service during enrollment — this is a dev-only fallback.
func loadOrCreatePepper(dataDir string) ([]byte, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(dataDir, "pepper")
	if b, err := os.ReadFile(path); err == nil {
		if len(b) != 32 {
			return nil, fmt.Errorf("pepper file has wrong length %d", len(b))
		}
		return b, nil
	}
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return nil, err
	}
	return b, nil
}

// Sensor returns the envelope.Sensor descriptor derived from config.
func (c *Config) Sensor(agentVersion string) envelope.Sensor {
	return envelope.Sensor{
		ID:           c.SensorID,
		Fleet:        c.Fleet,
		AgentVersion: agentVersion,
	}
}
