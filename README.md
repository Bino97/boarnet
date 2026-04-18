# boarnet-agent

Reference implementation of the BoarNet sensor agent, Go.

Single binary. Runs SSH + TLS honeypots on configured ports, extracts JA3 / HASSH fingerprints from incoming connections, buffers events locally in an encrypted SQLite file, and pushes batched [envelopes](../spec/envelope.md) to the BoarNet ingest service via mTLS HTTPS.

## Status

v0.1 — prototype. Compiles and runs standalone. Production features tracked as `TODO` in the code and summarized below.

## Build

```bash
cd agent
go mod tidy
make build          # -> ./bin/boarnet
```

Cross-compile for a Raspberry Pi:

```bash
make build-arm64    # -> ./bin/boarnet-linux-arm64
```

## Run

```bash
make run
```

Defaults:
- SSH honeypot on `:2222`
- TLS honeypot on `:8443`
- Buffer at `./.boarnet/buffer.db` (AES-GCM encrypted)
- Events POSTed to `http://localhost:3000/v1/events`

All overridable via flags — `boarnet --help`.

## What's implemented

- Envelope types matching [`spec/envelope.md` v1](../spec/envelope.md).
- SSH listener (session open + auth attempts) using `gliderlabs/ssh`.
- TLS ClientHello parser with JA3 string + MD5 hash (JA4 is a TODO — see `internal/honeypot/tls.go`).
- HMAC-SHA256 IP hashing with sensor pepper (see `internal/hash/hash.go`).
- SHA-256 credential hashing at the sensor before emission.
- Local SQLite event buffer with per-row AES-GCM encryption keyed from a file-on-disk master key (see `internal/buffer/buffer.go` — OS keystore integration is TODO).
- Batched HTTPS emitter with gzip, ULID batch IDs, exponential backoff + decorrelated jitter retry.
- Minimal heartbeat loop.

## What's TODO before production

| Area | Current | Production |
|---|---|---|
| Buffer-at-rest | File-based master key | OS keystore (Windows DPAPI, macOS Keychain, Linux libsecret) |
| Transport auth | Bearer token stub | mTLS with sensor-issued cert via enrollment flow |
| JA4 | JA3 only | Full JA4 via `FoxIO-LLC/ja4` port |
| SSH honeypot | Session + auth events | Medium interaction (command exec, fake FS) |
| HTTP honeypot | Not implemented | Basic auth + WordPress/phpMyAdmin lures |
| Enrollment | Not implemented | `boarnet enroll <token>` CLI |
| Config pull | Static flags | `/v1/config` polling |
| Dead-letter | In-memory | Persistent BoltDB bucket |
| Update channel | Manual rebuild | Signed-release pull |

## Layout

```
agent/
├── cmd/boarnet/main.go          # entrypoint, flag parsing, wiring
└── internal/
    ├── envelope/                 # envelope types + JSON marshaling
    ├── hash/                     # HMAC pepper + SHA256 credential hashing
    ├── buffer/                   # encrypted SQLite local queue
    ├── transport/                # batched HTTPS emitter, retry logic
    ├── honeypot/
    │   ├── ssh.go                # SSH honeypot (gliderlabs/ssh)
    │   └── tls.go                # TLS ClientHello parser + JA3
    └── config/                   # CLI flag → runtime config
```
