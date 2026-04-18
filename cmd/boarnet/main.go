// boarnet is the BoarNet sensor agent. It listens on configured
// honeypot ports, emits envelopes matching spec/envelope.md, buffers them
// locally in an encrypted SQLite file, and ships batches to the ingest
// service.
//
// This is v0.1. See ../../README.md for the current feature set and the TODO
// list of things that need to land before production.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Bino97/boarnet-agent/internal/buffer"
	"github.com/Bino97/boarnet-agent/internal/config"
	"github.com/Bino97/boarnet-agent/internal/envelope"
	"github.com/Bino97/boarnet-agent/internal/hash"
	"github.com/Bino97/boarnet-agent/internal/honeypot"
	"github.com/Bino97/boarnet-agent/internal/transport"
)

// version is stamped by the build (see Makefile).
var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
}

func run() error {
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	cfg, err := config.Parse(os.Args[1:])
	if err != nil {
		return err
	}
	log.Info("boarnet starting",
		"version", version,
		"sensor_id", cfg.SensorID,
		"fleet", cfg.Fleet,
	)

	buf, err := buffer.Open(cfg.DataDir)
	if err != nil {
		return fmt.Errorf("open buffer: %w", err)
	}
	defer buf.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	sensorInfo := cfg.Sensor(version)

	onEvent := func(env *envelope.Envelope) {
		if err := buf.Enqueue(ctx, env); err != nil {
			log.Error("enqueue failed", "event_id", env.EventID, "err", err)
		}
	}

	hostKey, err := loadOrCreateHostKey(cfg.DataDir)
	if err != nil {
		return fmt.Errorf("ssh host key: %w", err)
	}

	stopSSH, err := honeypot.StartSSH(ctx, honeypot.SSHConfig{
		Listen:     ":" + cfg.SSHPort,
		HostKey:    hostKey,
		Pepper:     cfg.Pepper,
		SensorInfo: sensorInfo,
		OnEvent:    onEvent,
		Log:        log,
	})
	if err != nil {
		return fmt.Errorf("start ssh honeypot: %w", err)
	}
	defer stopSSH()

	stopTLS, err := honeypot.StartTLS(ctx, honeypot.TLSConfig{
		Listen:     ":" + cfg.TLSPort,
		Pepper:     cfg.Pepper,
		SensorInfo: sensorInfo,
		OnEvent:    onEvent,
		Log:        log,
	})
	if err != nil {
		return fmt.Errorf("start tls honeypot: %w", err)
	}
	defer stopTLS()

	if cfg.HTTPPort != "" && cfg.HTTPPort != "0" {
		stopHTTP, err := honeypot.StartHTTP(ctx, honeypot.HTTPConfig{
			Listen:     ":" + cfg.HTTPPort,
			Pepper:     cfg.Pepper,
			SensorInfo: sensorInfo,
			OnEvent:    onEvent,
			Log:        log,
		})
		if err != nil {
			log.Error("start http honeypot failed (continuing)", "err", err)
		} else {
			defer stopHTTP()
		}
	}

	if len(cfg.SynSinkPorts) > 0 {
		stopSyn, err := honeypot.StartSYNSink(ctx, honeypot.SYNSinkConfig{
			Ports:      cfg.SynSinkPorts,
			Pepper:     cfg.Pepper,
			SensorInfo: sensorInfo,
			OnEvent:    onEvent,
			Log:        log,
		})
		if err != nil {
			log.Error("start synsink failed (continuing)", "err", err)
		} else {
			defer stopSyn()
		}
	}

	client := transport.New(cfg.IngestURL, cfg.Token, buf, log)

	go heartbeatLoop(ctx, buf, onEvent, sensorInfo, cfg.Pepper, log)

	log.Info("agent ready — draining buffer every 5s")
	return client.Run(ctx)
}

func heartbeatLoop(
	ctx context.Context,
	buf *buffer.Buffer,
	onEvent func(*envelope.Envelope),
	sensor envelope.Sensor,
	pepper hash.Pepper,
	log *slog.Logger,
) {
	start := time.Now()
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	// Pre-compute the self-IP hash once so every heartbeat uses the same value.
	// We use 0.0.0.0 as the conventional "not an attacker" source; the ingest
	// view excludes heartbeat events from threat rollups.
	selfIPHash, err := pepper.SrcIPHash("0.0.0.0")
	if err != nil {
		log.Error("pepper hashing failed", "err", err)
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			depth, _ := buf.Depth(ctx)
			raw := envelope.HeartbeatRaw{
				UptimeSeconds:  int64(time.Since(start).Seconds()),
				EventsBuffered: depth,
			}
			env := envelope.New(sensor, pepper.KeyID)
			env.EventType = envelope.EventSensorHeartbeat
			env.Src = envelope.Source{IP: "0.0.0.0", IPHash: selfIPHash, Port: 0}
			env.Dst = envelope.Destination{Port: 0, Proto: "tcp"}
			env.Fingerprints = envelope.Fingerprints{}
			body, _ := envelope.MarshalJSON(raw)
			env.Raw = body
			env.Tags = []string{"heartbeat"}
			onEvent(env)
			log.Debug("heartbeat", "buffered", depth)
		}
	}
}

// loadOrCreateHostKey reads or creates the SSH host key used by the
// honeypot. Persisting across restarts means scanner tooling sees a
// stable identity (matching fingerprint in their local known_hosts),
// which is important because a changing host key gets a connection
// flagged or abandoned by any adversary that cares.
//
// Stored in the existing data-dir next to the pepper + buffer, mode
// 0600. First run creates a fresh Ed25519 key.
func loadOrCreateHostKey(dataDir string) (ssh.Signer, error) {
	path := filepath.Join(dataDir, "ssh_host_ed25519_key")
	if b, err := os.ReadFile(path); err == nil {
		signer, err := ssh.ParsePrivateKey(b)
		if err == nil {
			return signer, nil
		}
		// Corrupt or wrong-type file; fall through to regen so the sensor
		// keeps running. The old file is overwritten.
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	pemBlock, err := ssh.MarshalPrivateKey(priv, "boarnet")
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := pem.Encode(&buf, pemBlock); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		return nil, fmt.Errorf("write host key: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(buf.Bytes())
	if err != nil {
		return nil, err
	}
	return signer, nil
}
