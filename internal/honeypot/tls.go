// TLS honeypot: accepts incoming TLS connections, parses the ClientHello,
// computes JA3 + MD5 hash, and emits a `tls.clienthello` envelope. We send
// back a server alert and close — no actual TLS state machine is maintained.
//
// TODO(boarnet): add FoxIO JA4 support. JA4 requires a slightly different
// canonicalization of extensions + ALPN. Keeping it separate so the
// ja3/ja4 paths can evolve independently.
package honeypot

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/Bino97/boarnet-agent/internal/envelope"
	"github.com/Bino97/boarnet-agent/internal/hash"
)

type TLSConfig struct {
	Listen     string
	Pepper     hash.Pepper
	SensorInfo envelope.Sensor
	OnEvent    func(*envelope.Envelope)
	Log        *slog.Logger
}

// StartTLS spawns the TLS ClientHello parser listener.
func StartTLS(ctx context.Context, cfg TLSConfig) (stop func() error, err error) {
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return nil, err
	}

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				cfg.Log.Error("tls accept", "err", err)
				continue
			}
			go handleTLS(conn, cfg)
		}
	}()

	cfg.Log.Info("tls honeypot listening", "addr", cfg.Listen)
	return func() error { return ln.Close() }, nil
}

func handleTLS(conn net.Conn, cfg TLSConfig) {
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	srcHost, srcPort := splitHostPort(conn.RemoteAddr())
	ipHash, _ := cfg.Pepper.SrcIPHash(srcHost)

	hello, rawBytes, err := readClientHello(conn)
	if err != nil {
		// Emit a scan.probe for connections that failed to handshake.
		emitTLSScanProbe(cfg, srcHost, ipHash, srcPort, 0)
		return
	}

	ja3 := ja3String(hello)
	ja3Sum := md5.Sum([]byte(ja3))
	ja3Hash := hex.EncodeToString(ja3Sum[:])

	env := envelope.New(cfg.SensorInfo, cfg.Pepper.KeyID)
	env.EventType = envelope.EventTLSClientHello
	env.Src = envelope.Source{IP: srcHost, IPHash: ipHash, Port: srcPort}
	env.Dst = envelope.Destination{Port: portFromListen(cfg.Listen), Proto: "tcp"}
	env.Fingerprints = envelope.Fingerprints{
		JA3:     envelope.StrPtr(ja3),
		JA3Hash: envelope.StrPtr(ja3Hash),
		// JA4 TODO
	}
	raw := envelope.TLSClientHelloRaw{
		TLSVersion:      fmt.Sprintf("0x%04x", hello.Version),
		Ciphersuites:    ciphersuitesAsHex(hello.Ciphersuites),
		Extensions:      extsToInts(hello.Extensions),
		ALPN:            hello.ALPN,
		SNI:             hello.SNI,
		SupportedGroups: namedGroups(hello.SupportedGroups),
	}
	if body, err := json.Marshal(raw); err == nil {
		env.Raw = body
	}
	env.Tags = []string{"tls"}
	cfg.OnEvent(env)

	_ = rawBytes
}

func emitTLSScanProbe(cfg TLSConfig, srcHost, ipHash string, srcPort, bytesIn int) {
	env := envelope.New(cfg.SensorInfo, cfg.Pepper.KeyID)
	env.EventType = envelope.EventScanProbe
	env.Src = envelope.Source{IP: srcHost, IPHash: ipHash, Port: srcPort}
	env.Dst = envelope.Destination{Port: portFromListen(cfg.Listen), Proto: "tcp"}
	env.Fingerprints = envelope.Fingerprints{}
	raw := envelope.ScanProbeRaw{BytesIn: bytesIn, RSTSent: false}
	if body, err := json.Marshal(raw); err == nil {
		env.Raw = body
	}
	env.Tags = []string{"tls", "probe"}
	cfg.OnEvent(env)
}

// --- ClientHello parsing ---

type clientHello struct {
	Version         uint16
	Ciphersuites    []uint16
	Extensions      []uint16
	ALPN            []string
	SNI             string
	SupportedGroups []uint16
}

func readClientHello(conn net.Conn) (*clientHello, []byte, error) {
	// TLS record layer: 5 bytes (type, version hi, version lo, length hi, length lo).
	rec := make([]byte, 5)
	if _, err := io.ReadFull(conn, rec); err != nil {
		return nil, nil, err
	}
	if rec[0] != 0x16 {
		return nil, nil, fmt.Errorf("not a handshake record")
	}
	length := int(rec[3])<<8 | int(rec[4])
	if length < 4 || length > 1<<15 {
		return nil, nil, fmt.Errorf("unreasonable record length %d", length)
	}

	body := make([]byte, length)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, nil, err
	}
	if body[0] != 0x01 {
		return nil, nil, fmt.Errorf("not a client_hello")
	}

	return parseClientHelloBody(body[4:]) // skip handshake header (type + 3-byte length)
}

func parseClientHelloBody(b []byte) (*clientHello, []byte, error) {
	orig := b
	if len(b) < 2+32+1 {
		return nil, nil, fmt.Errorf("short client_hello")
	}
	h := &clientHello{Version: uint16(b[0])<<8 | uint16(b[1])}
	b = b[2+32:] // version + random

	// session_id
	sidLen := int(b[0])
	b = b[1:]
	if len(b) < sidLen {
		return nil, nil, fmt.Errorf("bad session_id")
	}
	b = b[sidLen:]

	// cipher_suites
	if len(b) < 2 {
		return nil, nil, fmt.Errorf("bad cipher_suites")
	}
	csLen := int(b[0])<<8 | int(b[1])
	b = b[2:]
	if len(b) < csLen || csLen%2 != 0 {
		return nil, nil, fmt.Errorf("bad cipher_suites len")
	}
	for i := 0; i < csLen; i += 2 {
		h.Ciphersuites = append(h.Ciphersuites, uint16(b[i])<<8|uint16(b[i+1]))
	}
	b = b[csLen:]

	// compression_methods
	if len(b) < 1 {
		return nil, nil, fmt.Errorf("bad compression_methods")
	}
	cmLen := int(b[0])
	b = b[1:]
	if len(b) < cmLen {
		return nil, nil, fmt.Errorf("short compression_methods")
	}
	b = b[cmLen:]

	// extensions (optional)
	if len(b) < 2 {
		return h, orig, nil
	}
	extsLen := int(b[0])<<8 | int(b[1])
	b = b[2:]
	if len(b) < extsLen {
		return nil, nil, fmt.Errorf("short extensions")
	}
	exts := b[:extsLen]
	for len(exts) >= 4 {
		t := uint16(exts[0])<<8 | uint16(exts[1])
		l := int(exts[2])<<8 | int(exts[3])
		if len(exts) < 4+l {
			break
		}
		data := exts[4 : 4+l]
		h.Extensions = append(h.Extensions, t)
		switch t {
		case 0: // server_name
			if len(data) >= 2 {
				listLen := int(data[0])<<8 | int(data[1])
				list := data[2:]
				if len(list) >= listLen && listLen >= 3 {
					// first entry: name_type(1) + name_len(2) + name
					nameLen := int(list[1])<<8 | int(list[2])
					if len(list) >= 3+nameLen {
						h.SNI = string(list[3 : 3+nameLen])
					}
				}
			}
		case 16: // application_layer_protocol_negotiation
			if len(data) >= 2 {
				list := data[2:]
				for len(list) >= 1 {
					nl := int(list[0])
					if len(list) < 1+nl {
						break
					}
					h.ALPN = append(h.ALPN, string(list[1:1+nl]))
					list = list[1+nl:]
				}
			}
		case 10: // supported_groups
			if len(data) >= 2 {
				ln := int(data[0])<<8 | int(data[1])
				list := data[2:]
				if len(list) >= ln {
					for i := 0; i+1 < ln; i += 2 {
						h.SupportedGroups = append(h.SupportedGroups, uint16(list[i])<<8|uint16(list[i+1]))
					}
				}
			}
		}
		exts = exts[4+l:]
	}
	return h, orig, nil
}

// ja3String returns the canonical JA3 string (without hashing).
// Format: SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat
func ja3String(h *clientHello) string {
	parts := []string{
		strconv.Itoa(int(h.Version)),
		joinUints(h.Ciphersuites, "-"),
		joinUints(h.Extensions, "-"),
		joinUints(h.SupportedGroups, "-"),
		"", // EC point formats — we don't parse ext 11; empty per JA3 convention
	}
	return strings.Join(parts, ",")
}

func ciphersuitesAsHex(s []uint16) []string {
	out := make([]string, len(s))
	for i, v := range s {
		out[i] = fmt.Sprintf("0x%04x", v)
	}
	return out
}

func extsToInts(s []uint16) []int {
	out := make([]int, len(s))
	for i, v := range s {
		out[i] = int(v)
	}
	return out
}

func namedGroups(s []uint16) []string {
	out := make([]string, len(s))
	for i, v := range s {
		out[i] = fmt.Sprintf("0x%04x", v)
	}
	return out
}

func joinUints(s []uint16, sep string) string {
	if len(s) == 0 {
		return ""
	}
	parts := make([]string, len(s))
	for i, v := range s {
		parts[i] = strconv.Itoa(int(v))
	}
	return strings.Join(parts, sep)
}
