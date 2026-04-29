package honeypot

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"strconv"
	"time"

	"github.com/Bino97/boarnet-agent/internal/envelope"
	"github.com/Bino97/boarnet-agent/internal/hash"
)

// bannerHex returns the first min(len(b), 64) bytes as lowercase hex.
// Paired with sanitizePreview so proto-classify.ts can detect binary
// protocols that wouldn't survive the `.`-substitution in the hint
// (TLS ClientHello, SMB2, MSSQL TDS, Postgres SSLRequest, memcached
// binary). 64 bytes covers every canonical first-packet signature we
// care about and keeps the envelope's raw field under 200B per probe.
func bannerHex(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	cap := 64
	if len(b) < cap {
		cap = len(b)
	}
	return hex.EncodeToString(b[:cap])
}

// SYNSinkConfig wires a SYN-sink listener covering an arbitrary list of
// TCP ports. Each accepted connection records a scan.probe event and is
// closed after a short read window. Useful for catching port-scan
// sweeps that don't target SSH / TLS / HTTP specifically.
type SYNSinkConfig struct {
	Ports      []int
	Pepper     hash.Pepper
	SensorInfo envelope.Sensor
	OnEvent    func(*envelope.Envelope)
	Log        *slog.Logger
}

// Time we give an attacker to send first-contact bytes. Long enough to
// capture a typical banner/GET line; short enough that a 256-concurrent
// masscan sweep doesn't starve the agent on file descriptors.
const synReadWindow = 500 * time.Millisecond

// How many bytes to read for the banner hint. Enough for an HTTP
// request-line, an SMB negotiate, or a Redis PING; sanitized+truncated
// before emit.
const synReadCap = 256

func StartSYNSink(ctx context.Context, cfg SYNSinkConfig) (stop func() error, err error) {
	if len(cfg.Ports) == 0 {
		return func() error { return nil }, nil
	}
	listeners := make([]net.Listener, 0, len(cfg.Ports))
	for _, port := range cfg.Ports {
		addr := ":" + strconv.Itoa(port)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			cfg.Log.Warn("synsink listen failed (skipping port)", "port", port, "err", err)
			continue
		}
		listeners = append(listeners, ln)
		go servePort(ctx, cfg, ln, port)
	}
	if len(listeners) == 0 {
		return nil, net.ErrClosed
	}
	cfg.Log.Info("synsink listening", "ports", cfg.Ports, "accepted", len(listeners))

	return func() error {
		for _, ln := range listeners {
			_ = ln.Close()
		}
		return nil
	}, nil
}

func servePort(ctx context.Context, cfg SYNSinkConfig, ln net.Listener, port int) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			// On transient accept errors, log and keep going. net/http
			// server uses backoff here; for a passive listener just
			// loop — errors are rare and self-correct.
			cfg.Log.Debug("synsink accept err", "port", port, "err", err)
			return
		}
		go handleSYN(cfg, conn, port)
	}
}

func handleSYN(cfg SYNSinkConfig, conn net.Conn, port int) {
	defer conn.Close()
	start := time.Now()

	srcHost, srcPort := splitHostPort(conn.RemoteAddr())
	ipHash, _ := cfg.Pepper.SrcIPHash(srcHost)

	// Read a small window of first-contact bytes. Most scanners either
	// send something small immediately (GET /, SMB Negotiate, …) or
	// nothing at all (pure SYN scan → we get 0 bytes).
	_ = conn.SetReadDeadline(time.Now().Add(synReadWindow))
	buf := make([]byte, synReadCap)
	n, _ := io.ReadFull(conn, buf)
	if n == 0 {
		// Non-ReadFull path: try a short read even if ReadFull gave 0
		// (e.g. single byte and EOF). errors.Is ignored on purpose.
		m, _ := conn.Read(buf)
		n = m
	}

	raw := envelope.ScanProbeRaw{
		DurationMS: int(time.Since(start).Milliseconds()),
		BytesIn:    n,
		BytesOut:   0,
		RSTSent:    false,
		BannerHint: sanitizePreview(buf[:n]),
		BannerHex:  bannerHex(buf[:n]),
	}

	env := envelope.New(cfg.SensorInfo, cfg.Pepper.KeyID)
	env.EventType = envelope.EventScanProbe
	env.Src = envelope.Source{IP: srcHost, IPHash: ipHash, Port: srcPort}
	env.Dst = envelope.Destination{Port: port, Proto: "tcp"}
	env.Fingerprints = envelope.Fingerprints{}
	env.Tags = tagsForSYN(port, buf[:n])
	if body, err := json.Marshal(raw); err == nil {
		env.Raw = body
	}
	cfg.OnEvent(env)
}

// Tag each probe with its destination-port's conventional protocol so
// Explore can facet by service without an external lookup.
func tagsForSYN(port int, banner []byte) []string {
	tags := []string{"probe"}
	switch port {
	case 21:
		tags = append(tags, "ftp")
	case 23:
		tags = append(tags, "telnet")
	case 25, 465, 587:
		tags = append(tags, "smtp")
	case 53:
		tags = append(tags, "dns")
	case 110, 995:
		tags = append(tags, "pop3")
	case 143, 993:
		tags = append(tags, "imap")
	case 445:
		tags = append(tags, "smb")
	case 1433, 1521:
		tags = append(tags, "db", "mssql-or-oracle")
	case 3306:
		tags = append(tags, "db", "mysql")
	case 3389:
		tags = append(tags, "rdp")
	case 5432:
		tags = append(tags, "db", "postgres")
	case 5900, 5901:
		tags = append(tags, "vnc")
	case 6379:
		tags = append(tags, "redis")
	case 9200, 9300:
		tags = append(tags, "elasticsearch")
	case 11211:
		tags = append(tags, "memcached")
	case 27017:
		tags = append(tags, "mongodb")
	}

	// If the client sent HTTP — e.g. `GET / HTTP/1.0` against a port
	// they think is a web server — surface that regardless of port.
	if len(banner) >= 4 {
		first := string(banner[:4])
		if first == "GET " || first == "HEAD" || first == "POST" {
			tags = append(tags, "http-on-nonstd")
		}
	}
	return tags
}
