// TLS honeypot: accepts incoming TLS connections, parses the ClientHello,
// computes both the legacy JA3 (SSL-era) and FoxIO's JA4 fingerprints,
// and emits a `tls.clienthello` envelope. We send back a server alert and
// close — no actual TLS state machine is maintained.
//
// JA4 reference: https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
package honeypot

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sort"
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
	ja4 := ja4Fingerprint(hello)
	env.Fingerprints = envelope.Fingerprints{
		JA3:     envelope.StrPtr(ja3),
		JA3Hash: envelope.StrPtr(ja3Hash),
		JA4:     envelope.StrPtr(ja4),
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
	Version           uint16
	Ciphersuites      []uint16
	Extensions        []uint16 // order as seen on the wire
	ALPN              []string
	SNI               string
	SupportedGroups   []uint16
	SupportedVersions []uint16 // from extension 43 (0x002b)
	SignatureAlgs     []uint16 // from extension 13 (0x000d), wire order preserved
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
		case 13: // signature_algorithms — JA4 second hash uses these in
			// *wire order*, not sorted. The inner structure is a
			// 2-byte length prefix then N 2-byte sig-alg codes.
			if len(data) >= 2 {
				ln := int(data[0])<<8 | int(data[1])
				list := data[2:]
				if len(list) >= ln {
					for i := 0; i+1 < ln; i += 2 {
						h.SignatureAlgs = append(h.SignatureAlgs, uint16(list[i])<<8|uint16(list[i+1]))
					}
				}
			}
		case 43: // supported_versions (client). 1-byte list length then
			// N 2-byte version codes. Used for JA4's version digit:
			// TLS 1.3 advertises via this extension instead of the
			// legacy_version field which stays pinned at 0x0303.
			if len(data) >= 1 {
				ln := int(data[0])
				list := data[1:]
				if len(list) >= ln {
					for i := 0; i+1 < ln; i += 2 {
						h.SupportedVersions = append(h.SupportedVersions, uint16(list[i])<<8|uint16(list[i+1]))
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

// ------------- JA4 -------------
//
// Fingerprint format:
//   {proto}{ver}{sni}{cipherCount:2d}{extCount:2d}{alpn2} _ cipherHash12 _ extSigHash12
//
// - proto: 't' (TLS), 'q' (QUIC), 'd' (DTLS). We only accept TLS here.
// - ver:   two-char version code derived from the MAX of supported_versions
//          (ext 43) if present, otherwise the legacy_version field.
// - sni:   'd' if SNI extension was present with a domain, 'i' otherwise.
// - cipherCount/extCount: decimal counts with GREASE values excluded.
//          Extension count further excludes SNI (0) and ALPN (16).
// - alpn2: first + last character of the first ALPN value, or "00" if
//          no ALPN extension. Non-ASCII/non-printable → "99".
// - cipherHash12: first 12 hex of sha256 of comma-joined sorted ciphers
//                 (lowercase 4-digit hex, GREASE excluded).
// - extSigHash12: first 12 hex of sha256 of
//                   <comma-joined sorted exts>_<comma-joined wire-order sig-algs>
//                 (lowercase 4-digit hex, GREASE + SNI + ALPN excluded
//                 from the ext set; sig-algs NOT sorted).
//
// When a section has no members the canonical form uses 12 zeros
// instead of hashing the empty string, per FoxIO's reference impl.

func isGREASE(v uint16) bool {
	hi := byte(v >> 8)
	lo := byte(v & 0xff)
	return hi == lo && (lo&0x0f) == 0x0a
}

func ja4VersionCode(h *clientHello) string {
	// Pick the highest non-GREASE supported_version; fall back to
	// legacy_version when the extension wasn't sent.
	best := uint16(0)
	for _, v := range h.SupportedVersions {
		if isGREASE(v) {
			continue
		}
		if v > best {
			best = v
		}
	}
	if best == 0 {
		best = h.Version
	}
	switch best {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0200:
		return "s2"
	}
	return "00"
}

func ja4AlpnCode(h *clientHello) string {
	if len(h.ALPN) == 0 || len(h.ALPN[0]) == 0 {
		return "00"
	}
	a := h.ALPN[0]
	first, last := a[0], a[len(a)-1]
	// Per FoxIO JA4 spec: use the first and last ASCII alphanumeric
	// character of the first ALPN value. When either byte is
	// non-alphanumeric, fall back to the first hex-nibble of the first
	// byte concatenated with the last hex-nibble of the last byte. So
	// `0xAB 0xCD` → "ad"; `0x30 0xAB` → "3b".
	ok := func(c byte) bool {
		return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
	}
	if !ok(first) || !ok(last) {
		const hexc = "0123456789abcdef"
		return string([]byte{hexc[first>>4], hexc[last&0x0f]})
	}
	return string([]byte{first, last})
}

func sha12(input string) string {
	if input == "" {
		return "000000000000"
	}
	sum := sha256.Sum256([]byte(input))
	return hex.EncodeToString(sum[:])[:12]
}

func joinHexSorted(vals []uint16) string {
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		if isGREASE(v) {
			continue
		}
		out = append(out, fmt.Sprintf("%04x", v))
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

func joinHexWire(vals []uint16) string {
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		if isGREASE(v) {
			continue
		}
		out = append(out, fmt.Sprintf("%04x", v))
	}
	return strings.Join(out, ",")
}

func ja4Fingerprint(h *clientHello) string {
	// Cipher list — GREASE filtered; sorted for the hash input and for
	// the count, so a reordered-but-same-set ClientHello hashes identically.
	var ciphers []uint16
	for _, c := range h.Ciphersuites {
		if !isGREASE(c) {
			ciphers = append(ciphers, c)
		}
	}

	// Extensions for the hash: exclude GREASE, SNI (0), ALPN (16). The
	// count includes SNI/ALPN but excludes GREASE — two different sets.
	var extsForCount []uint16
	var extsForHash []uint16
	for _, e := range h.Extensions {
		if isGREASE(e) {
			continue
		}
		extsForCount = append(extsForCount, e)
		if e == 0 || e == 16 {
			continue
		}
		extsForHash = append(extsForHash, e)
	}

	sniFlag := "i"
	if h.SNI != "" {
		sniFlag = "d"
	}

	prefix := fmt.Sprintf(
		"t%s%s%02d%02d%s",
		ja4VersionCode(h),
		sniFlag,
		min2d(len(ciphers)),
		min2d(len(extsForCount)),
		ja4AlpnCode(h),
	)

	cipherHash := sha12(joinHexSorted(ciphers))

	var extSigInput string
	if len(extsForHash) == 0 && len(h.SignatureAlgs) == 0 {
		extSigInput = ""
	} else {
		extSigInput = joinHexSorted(extsForHash) + "_" + joinHexWire(h.SignatureAlgs)
	}
	extSigHash := sha12(extSigInput)

	return prefix + "_" + cipherHash + "_" + extSigHash
}

// min2d clamps a count to the 00..99 two-digit JA4 field.
func min2d(n int) int {
	if n > 99 {
		return 99
	}
	if n < 0 {
		return 0
	}
	return n
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
