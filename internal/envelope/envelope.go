// Package envelope defines the v1 BoarNet event envelope as specified in
// spec/envelope.md. Every envelope the agent emits goes through these types.
package envelope

import (
	"encoding/json"
	"time"

	"github.com/oklog/ulid/v2"
)

const EnvelopeVersion = 1

// EventType enumerates the v1 event types.
type EventType string

const (
	EventSSHSessionOpen EventType = "ssh.session.open"
	EventSSHAuthAttempt EventType = "ssh.auth.attempt"
	EventSSHCmdExec     EventType = "ssh.cmd.exec"
	EventTLSClientHello EventType = "tls.clienthello"
	EventHTTPRequest    EventType = "http.request"
	EventPayloadDropped EventType = "payload.dropped"
	EventScanProbe      EventType = "scan.probe"
	EventSensorHeartbeat EventType = "sensor.heartbeat"
)

// Fleet is the sensor fleet classification.
type Fleet string

const (
	FleetCore Fleet = "core"
	FleetMesh Fleet = "mesh"
)

// Envelope is the root type all events share.
type Envelope struct {
	Version         int              `json:"envelope_version"`
	EventID         string           `json:"event_id"`
	EventType       EventType        `json:"event_type"`
	TS              time.Time        `json:"ts"`
	Sensor          Sensor           `json:"sensor"`
	Src             Source           `json:"src"`
	Dst             Destination      `json:"dst"`
	Fingerprints    Fingerprints     `json:"fingerprints"`
	Raw             json.RawMessage  `json:"raw"`
	Tags            []string         `json:"tags,omitempty"`
	EncryptionHints EncryptionHints  `json:"encryption_hints"`
}

type Sensor struct {
	ID           string `json:"id"`
	Fleet        Fleet  `json:"fleet"`
	AgentVersion string `json:"agent_version"`
}

type Source struct {
	IP     string `json:"ip"`
	IPHash string `json:"ip_hash"`
	Port   int    `json:"port"`
}

type Destination struct {
	Port  int    `json:"port"`
	Proto string `json:"proto"` // tcp, udp
}

// Fingerprints — any field is explicitly nullable, never omitted. We
// serialize pointer-strings so unset fields appear as `null`.
type Fingerprints struct {
	JA3     *string `json:"ja3"`
	JA3Hash *string `json:"ja3_hash"`
	JA4     *string `json:"ja4"`
	SSH     *string `json:"ssh"`
}

type EncryptionHints struct {
	SensorEncryptedFields []string `json:"sensor_encrypted_fields"`
	PepperKeyID           string   `json:"pepper_key_id"`
}

// New creates a fresh envelope stamped with a ULID event_id and current time.
// Caller fills in EventType, Src, Dst, Fingerprints, Raw, and optional Tags.
func New(sensor Sensor, pepperKeyID string) *Envelope {
	return &Envelope{
		Version: EnvelopeVersion,
		EventID: ulid.Make().String(),
		TS:      time.Now().UTC(),
		Sensor:  sensor,
		EncryptionHints: EncryptionHints{
			SensorEncryptedFields: []string{},
			PepperKeyID:           pepperKeyID,
		},
	}
}

// --- raw payload shapes ---

type SSHSessionOpenRaw struct {
	ClientBanner  string `json:"client_banner"`
	Kex           string `json:"kex,omitempty"`
	Cipher        string `json:"cipher,omitempty"`
	MAC           string `json:"mac,omitempty"`
	Compression   string `json:"compression,omitempty"`
	ClientVersion string `json:"client_version"`
}

type SSHAuthAttemptRaw struct {
	SessionID       string `json:"session_id"`
	Method          string `json:"method"`
	Username        string `json:"username"`
	CredentialHint  string `json:"credential_hint"` // always "sha256:<hex>"
}

type SSHCmdExecRaw struct {
	SessionID string `json:"session_id"`
	Command   string `json:"command"`
	PID       int    `json:"pid,omitempty"`
	CWD       string `json:"cwd,omitempty"`
	ExitCode  int    `json:"exit_code,omitempty"`
}

type TLSClientHelloRaw struct {
	TLSVersion      string   `json:"tls_version"`
	Ciphersuites    []string `json:"ciphersuites"`
	Extensions      []int    `json:"extensions"`
	ALPN            []string `json:"alpn,omitempty"`
	SNI             string   `json:"sni,omitempty"`
	SupportedGroups []string `json:"supported_groups,omitempty"`
}

type ScanProbeRaw struct {
	DurationMS int  `json:"duration_ms"`
	BytesIn    int  `json:"bytes_in"`
	BytesOut   int  `json:"bytes_out"`
	RSTSent    bool `json:"rst_sent"`
}

type HeartbeatRaw struct {
	UptimeSeconds    int64   `json:"uptime_seconds"`
	EventsBuffered   int     `json:"events_buffered"`
	EventsSentTotal  int64   `json:"events_sent_total"`
	LocalTimeSkewMS  int     `json:"local_time_skew_ms"`
	CPUPercent       float64 `json:"cpu_percent"`
	RSSMB            float64 `json:"rss_mb"`
}

// StrPtr returns a pointer to the string, for the Fingerprints nullable fields.
func StrPtr(s string) *string { return &s }

// Batch is the wire-format wrapper sent to POST /v1/events.
type Batch struct {
	BatchID   string      `json:"batch_id"`
	SentAt    time.Time   `json:"sent_at"`
	Envelopes []*Envelope `json:"envelopes"`
}

func NewBatch(envs []*Envelope) *Batch {
	return &Batch{
		BatchID:   ulid.Make().String(),
		SentAt:    time.Now().UTC(),
		Envelopes: envs,
	}
}

// MarshalJSON is a package-level helper so callers don't have to import
// encoding/json just to serialize a raw body into an envelope.
func MarshalJSON(v any) ([]byte, error) {
	return json.Marshal(v)
}
