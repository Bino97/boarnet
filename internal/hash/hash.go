// Package hash contains the sensor-side cryptographic primitives that run
// before an envelope is emitted: HMAC-SHA256 for queryable identifiers (IP,
// future fields) and SHA-256 for credentials. See spec/envelope.md §
// "Sensor-side cryptography".
package hash

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

// Pepper carries the HMAC secret plus its generation ID so envelopes can
// declare which pepper produced their HMACs.
type Pepper struct {
	KeyID  string // e.g. "pepper-2026q2"
	Secret []byte // 32 bytes
}

// SrcIPHash normalizes the IP and returns "hmac-sha256:<hex>".
func (p Pepper) SrcIPHash(ip string) (string, error) {
	if len(p.Secret) < 32 {
		return "", fmt.Errorf("pepper too short: need 32 bytes, got %d", len(p.Secret))
	}
	norm := normalizeIP(ip)
	mac := hmac.New(sha256.New, p.Secret)
	mac.Write([]byte(norm))
	return "hmac-sha256:" + hex.EncodeToString(mac.Sum(nil)), nil
}

// normalizeIP canonicalizes an IP so the same address always hashes the same:
// IPv4 dotted-quad, IPv6 lowercased compressed form.
func normalizeIP(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ip // best-effort; caller passed something non-standard
	}
	if v4 := parsed.To4(); v4 != nil {
		return v4.String()
	}
	return strings.ToLower(parsed.String())
}

// CredentialHint returns "sha256:<hex>" over the attempted credential. The
// agent hashes passwords before emission; ingest rejects plaintext.
func CredentialHint(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return "sha256:" + hex.EncodeToString(sum[:])
}
