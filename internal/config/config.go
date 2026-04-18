// Package config turns CLI flags into runtime configuration for the agent.
package config

import (
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Bino97/boarnet-agent/internal/envelope"
	"github.com/Bino97/boarnet-agent/internal/hash"
)

type Config struct {
	SensorID     string
	Fleet        envelope.Fleet
	SSHPort      string
	TLSPort      string
	HTTPPort     string  // "" or "0" disables
	SynSinkPorts []int   // empty disables
	IngestURL    string
	Token        string // TODO: replace with mTLS
	DataDir      string
	PepperKeyID  string
	Pepper       hash.Pepper
}

// Ports covered by the SYN sink out-of-the-box. Pragmatic pick: common
// scanner targets that won't collide with the dedicated SSH / TLS / HTTP
// honeypots. Port 22 is intentionally excluded — the host's real sshd
// typically owns it. Operator can override with --synsink-ports.
const DefaultSynSinkPorts = "21,23,25,110,139,445,1433,3306,3389,5432,5900,6379,9200,11211,27017"

func Parse(args []string) (*Config, error) {
	fs := flag.NewFlagSet("boarnet", flag.ContinueOnError)

	cfg := &Config{}
	fs.StringVar(&cfg.SensorID, "sensor-id", "dev-local", "registered sensor id")
	fleet := fs.String("fleet", "mesh", "fleet: core | mesh")
	fs.StringVar(&cfg.SSHPort, "ssh-port", "2222", "ssh honeypot listen port")
	fs.StringVar(&cfg.TLSPort, "tls-port", "8443", "tls honeypot listen port")
	fs.StringVar(&cfg.HTTPPort, "http-port", "8080", "http honeypot listen port (empty or 0 disables)")
	synsink := fs.String("synsink-ports", DefaultSynSinkPorts, "comma-separated TCP ports for the SYN-sink catcher; empty disables")
	fs.StringVar(&cfg.IngestURL, "ingest-url", "http://localhost:3000/v1/events", "ingest service URL")
	fs.StringVar(&cfg.Token, "token", "", "bearer token (TEMPORARY — mTLS supersedes this)")
	fs.StringVar(&cfg.DataDir, "data-dir", ".boarnet", "where to keep buffer, pepper, key")
	fs.StringVar(&cfg.PepperKeyID, "pepper-key-id", "pepper-dev", "HMAC pepper generation id")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	cfg.SynSinkPorts = parsePortList(*synsink)

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

// parsePortList turns "23,80,443" into []int. Invalid / out-of-range
// entries are silently dropped so a typo in one port doesn't kill the
// whole sensor.
func parsePortList(s string) []int {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	out := make([]int, 0)
	for _, raw := range strings.Split(s, ",") {
		part := strings.TrimSpace(raw)
		if part == "" {
			continue
		}
		n, err := strconv.Atoi(part)
		if err != nil || n < 1 || n > 65535 {
			continue
		}
		out = append(out, n)
	}
	return out
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
