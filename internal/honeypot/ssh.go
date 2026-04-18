// Package honeypot contains the sensor-side network listeners. The SSH
// listener accepts incoming connections, records session-open and auth-attempt
// events, and denies every auth. No shell is ever granted — that's Cowrie's
// job if the operator opts into the full-interaction bundle.
package honeypot

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"

	gossh "github.com/gliderlabs/ssh"
	"golang.org/x/crypto/ssh"

	"github.com/Bino97/boarnet-agent/internal/envelope"
	"github.com/Bino97/boarnet-agent/internal/hash"
)

type SSHConfig struct {
	Listen     string // ":2222"
	HostKey    ssh.Signer
	Pepper     hash.Pepper
	SensorInfo envelope.Sensor
	OnEvent    func(*envelope.Envelope)
	Log        *slog.Logger
}

// StartSSH spawns the SSH honeypot. Returns a stop function and an error if
// the listener could not be created.
func StartSSH(ctx context.Context, cfg SSHConfig) (stop func() error, err error) {
	server := &gossh.Server{
		Addr: cfg.Listen,
	}

	if cfg.HostKey != nil {
		server.AddHostKey(cfg.HostKey)
	}

	// TODO(boarnet): emit `ssh.session.open` once we can capture the client
	// banner. ConnCallback fires before the SSH banner exchange so
	// ctx.ClientVersion() is empty there; the cleanest fix is to snoop the
	// first line of raw bytes on the net.Conn. For v0.1 we only emit
	// auth.attempt events — they already carry everything the rollup needs.

	// Every password attempt → ssh.auth.attempt, always deny.
	server.PasswordHandler = func(ctx gossh.Context, password string) bool {
		srcHost, srcPort := splitHostPort(ctx.RemoteAddr())
		ipHash, _ := cfg.Pepper.SrcIPHash(srcHost)

		raw := envelope.SSHAuthAttemptRaw{
			SessionID:      ctx.SessionID(),
			Method:         "password",
			Username:       ctx.User(),
			CredentialHint: hash.CredentialHint(password),
		}
		emit(cfg, envelope.EventSSHAuthAttempt, srcHost, ipHash, srcPort, raw, []string{"ssh", "bruteforce-candidate"})
		return false
	}

	server.PublicKeyHandler = func(ctx gossh.Context, key gossh.PublicKey) bool {
		srcHost, srcPort := splitHostPort(ctx.RemoteAddr())
		ipHash, _ := cfg.Pepper.SrcIPHash(srcHost)

		raw := envelope.SSHAuthAttemptRaw{
			SessionID:      ctx.SessionID(),
			Method:         "publickey",
			Username:       ctx.User(),
			CredentialHint: hash.CredentialHint(string(key.Marshal())),
		}
		emit(cfg, envelope.EventSSHAuthAttempt, srcHost, ipHash, srcPort, raw, []string{"ssh", "publickey"})
		return false
	}

	// Deny any shell/exec request (belt + suspenders — PasswordHandler already returns false).
	server.Handler = func(sess gossh.Session) {
		sess.Exit(1)
	}

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return nil, err
	}

	go func() {
		if err := server.Serve(ln); err != nil && ctx.Err() == nil {
			cfg.Log.Error("ssh server stopped", "err", err)
		}
	}()

	cfg.Log.Info("ssh honeypot listening", "addr", cfg.Listen)

	return func() error {
		return server.Close()
	}, nil
}

func splitHostPort(addr net.Addr) (string, int) {
	tcp, ok := addr.(*net.TCPAddr)
	if !ok {
		return addr.String(), 0
	}
	return tcp.IP.String(), tcp.Port
}

func emit(
	cfg SSHConfig,
	et envelope.EventType,
	srcIP, srcIPHash string,
	srcPort int,
	raw any,
	tags []string,
) {
	// Hard-coded pepper key id taken from the pepper — see envelope.md §
	// "Sensor-side cryptography".
	env := envelope.New(cfg.SensorInfo, cfg.Pepper.KeyID)
	env.EventType = et
	env.Src = envelope.Source{IP: srcIP, IPHash: srcIPHash, Port: srcPort}
	env.Dst = envelope.Destination{Port: portFromListen(cfg.Listen), Proto: "tcp"}
	env.Fingerprints = envelope.Fingerprints{}
	if tags != nil {
		env.Tags = tags
	}
	if raw != nil {
		body, err := json.Marshal(raw)
		if err == nil {
			env.Raw = body
		}
	}
	cfg.OnEvent(env)
}

func portFromListen(addr string) int {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	var p int
	_, _ = fmt.Sscanf(portStr, "%d", &p)
	return p
}
