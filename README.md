# BoarNet Agent

A passive honeypot + threat-intel sensor written in Go. Single static binary,
runs on any Linux box (VPS, Pi, or whatever's in your homelab). Listens on
honeypot ports, fingerprints attackers (JA3/JA4, ASN, ports, payloads), and
streams events to the BoarNet network for free Pro API access while it's
reporting.

[![Latest release](https://img.shields.io/github/v/release/Bino97/boarnet?label=release&style=flat-square)](https://github.com/Bino97/boarnet/releases/latest)
[![License: MIT](https://img.shields.io/github/license/Bino97/boarnet?style=flat-square)](LICENSE)
[![Go version](https://img.shields.io/github/go-mod/go-version/Bino97/boarnet?style=flat-square)](go.mod)

— Platform: <https://www.boarnet.io>
— Sign up + token: <https://www.boarnet.io/signup?next=/onboarding>
— Lander for self-hosters: <https://www.boarnet.io/mesh>

## What it does

- **SSH/TLS/HTTP honeypot listeners** on commonly-probed ports (22, 23, 80,
  443, 8080, 8443, plus a SYN-sink across 21/25/110/139/445/1433/3306/3389/
  5432/5900/6379/9200/11211/27017).
- **JA3 + JA4 fingerprinting** on every TLS handshake. Hashes get submitted
  to BoarNet so attackers can be tracked across IP rotation by the tools
  they use, not the addresses they come from.
- **HMAC-SHA256 IP hashing** before emission with a per-sensor pepper, so
  raw source IPs never leave the box untransformed.
- **Encrypted local buffer** (SQLite + AES-GCM) for offline resilience.
  Events queue locally if the ingest endpoint is unreachable, replay on
  recovery.
- **Batched HTTPS emitter** with gzip + exponential backoff. Designed to
  stay quiet on the network when nothing is happening.
- **Egress lockdown friendly**: the agent only ever calls
  `https://www.boarnet.io`. Pin that with iptables and you have a
  honeypot that physically cannot talk anywhere else.

## Install

### One-liner (Linux, x86_64 / arm64)

```bash
curl -fsSL https://boarnet.io/install.sh | sudo bash
```

Detects your arch, downloads the latest signed release into
`/usr/local/bin/boarnet`, verifies the SHA256, and sets up a systemd unit
when run as root.

### Build from source

```bash
git clone https://github.com/Bino97/boarnet.git
cd boarnet
go build -o boarnet ./cmd/boarnet
```

### Docker

A published image at `ghcr.io/bino97/boarnet` is on the roadmap. Until
then, use the install.sh path or build from source. If you want to wrap
the binary in your own Dockerfile in the meantime, the included
[`Dockerfile`](Dockerfile) is a starting point.

## Run

```bash
boarnet \
  --fleet mesh \
  --sensor-id $(hostname) \
  --ingest-url https://www.boarnet.io/api/ingest/v1/events \
  --token bn_<paste-your-token> \
  --data-dir /var/lib/boarnet
```

Get a token: <https://www.boarnet.io/onboarding> (30-second signup, no card,
token shows immediately). Your account is promoted to Participant tier the
moment the first event lands — full Pro API access while a sensor is
reporting.

`boarnet --help` for the full flag list. `boarnet --version` to confirm
which release you are running.

## What you can audit

Everything you actually run is in this repo. Skim it before you trust it:

- [`cmd/boarnet/main.go`](cmd/boarnet/main.go) — entrypoint, flag parsing, wiring.
- [`internal/honeypot/`](internal/honeypot) — SSH, TLS, HTTP listeners. JA3/JA4 extraction.
- [`internal/hash/`](internal/hash) — HMAC + SHA256 source-IP hashing.
- [`internal/buffer/`](internal/buffer) — encrypted local SQLite queue.
- [`internal/transport/`](internal/transport) — batched HTTPS emitter, retry logic.
- [`internal/envelope/`](internal/envelope) — wire format. Spec in [`spec/envelope.md`](spec/envelope.md).
- [`internal/config/`](internal/config) — flag → runtime config.

The only thing not in this repo is the BoarNet platform itself (ingest
endpoint, dashboard, network analysis). That lives separately because it
does not need to run on your box.

## License

[MIT](LICENSE). Run it, fork it, embed it. If you publish a fork that talks
to a different ingest endpoint, that is your network — go for it.

## Security

Found a vuln? Email security@boarnet.io or open a private security advisory
on GitHub. Agent-side issues are P0 — your network is running this code and
we owe you a fast response.

## Releases

See [Releases](https://github.com/Bino97/boarnet/releases). Each tag ships
prebuilt binaries for `linux-amd64`, `linux-arm64`, `darwin-amd64`, and
`darwin-arm64`, plus a `SHA256SUMS` file. The install.sh script verifies
the checksum before swapping the binary in place.
