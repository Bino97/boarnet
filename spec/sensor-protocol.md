# BoarNet Sensor → Ingest Protocol — v1

Status: **draft**
Owner: BoarNet
Last updated: 2026-04-17

This is the wire protocol between a running sensor agent and the BoarNet ingestion service. It defines authentication, batching, retry, enrollment, and heartbeats. Payload shape is defined in [`envelope.md`](./envelope.md).

## Endpoints

Base URL per environment:
- Production: `https://ingest.boarnet.local`
- Staging: `https://ingest.staging.boarnet.local`

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/v1/enroll` | One-time enrollment, exchanges an enrollment token for a long-lived agent cert. |
| `POST` | `/v1/events` | Primary submission endpoint. Accepts a batch of envelopes. |
| `POST` | `/v1/heartbeat` | Dedicated heartbeat for rate-limited fleet visibility. Optional shortcut — heartbeats via `/v1/events` also work. |
| `GET` | `/v1/config` | Agent pulls server-side config (enabled honeypot types, sampling rates, target ports) on a 15-min interval. |

## Authentication

**Primary: mTLS.** Every authenticated request presents a client cert issued at enrollment. The cert is signed by the BoarNet Root CA and contains the `sensor_id` in the CN. Ingest verifies the cert at TLS termination.

**Fallback / bootstrap: enrollment token.** A single-use, short-lived token (24 h TTL) that operators paste into the agent to claim a sensor_id. Only `/v1/enroll` accepts token auth.

**Why not just Bearer:** Bearer tokens are simpler but would require header-inspection and rotation at every request; mTLS pushes the auth cost into the TLS handshake and terminates it at the edge. It also means a compromised log file never contains a useful credential.

## Enrollment flow

```
operator             agent                    ingest
   │                   │                         │
   │ mints token ──────┼──────────── via admin ──▶ (db: enrollment_tokens)
   │   token=ET-...    │                         │
   │                   │                         │
   │── pastes token ──▶│                         │
   │                   │── POST /v1/enroll ─────▶│ verifies token
   │                   │   { token, pub_key }    │
   │                   │◀── 201 ─────────────────│ issues cert
   │                   │   { sensor_id, cert,    │
   │                   │     ca_chain, expires } │
   │                   │                         │
   │                   │ writes cert + key       │
   │                   │ to ~/.boarnet/         │
   │                   │                         │
   │                   │── POST /v1/heartbeat ──▶│ (mTLS)
   │                   │◀── 200 ─────────────────│
```

Cert expiry: 90 days. Agent rotates automatically at 80% of lifetime by calling `POST /v1/enroll/rotate` with the current cert.

## Batching

Agents buffer events locally (SQLite) and POST in batches to `/v1/events`.

### Batch format

```json
{
  "batch_id": "01HKQAE6VCNPT7BCP0WQG0P3ZB",
  "sent_at": "2026-04-18T01:59:35.412Z",
  "envelopes": [
    { /* envelope */ },
    { /* envelope */ },
    ...
  ]
}
```

### Batching rules

- **Flush triggers (first to fire):** 100 events buffered, **or** 30 s since oldest buffered event, **or** buffer at 50 MB, **or** explicit shutdown.
- **Max batch size:** 500 envelopes or 5 MB compressed, whichever first. Larger gets split.
- **Compression:** `gzip`. Always. `Content-Encoding: gzip`.
- **Content-Type:** `application/json`.
- **Ordering:** envelopes within a batch are in monotonic `ts` order. Not guaranteed across batches (delivery is at-least-once, not ordered across retries).

### Response

```json
{
  "accepted": 97,
  "rejected": [
    { "event_id": "01HKQA...Z", "reason": "invalid_event_type" },
    { "event_id": "01HKQA...Y", "reason": "src.ip_bogon" },
    { "event_id": "01HKQA...X", "reason": "duplicate" }
  ],
  "throttle_hint_seconds": 0
}
```

Rejected events are **not** retried — the agent logs them and moves on. This prevents malformed sensors from looping forever.

## Retry

Transient failures (5xx, network errors, timeouts) retry with **exponential backoff + decorrelated jitter**:

```
base = 2s
cap = 300s
attempt[n] = min(cap, random(base, base * 3^n))
```

- Max attempts: 7 before the batch is written to the local **dead-letter queue** (a BoltDB bucket that the agent reports on at each heartbeat).
- Non-retryable errors: 400 (malformed batch — likely a schema drift bug, log loudly), 401 (auth failed — halt and surface to operator), 404 (unknown endpoint — probably a version mismatch).

## Rate limiting

Ingest enforces a per-sensor rate limit.

- **Default:** 2,000 envelopes/minute per sensor_id.
- **Burst:** up to 5,000 in a 10 s window.
- Limit response: `429` with `Retry-After` (seconds) and `throttle_hint_seconds` in body. Agent backs off; events go to buffer, not dead-letter.

For Verified Core sensors the limit is 20,000/minute — set by the operator, not negotiable from the sensor side.

## Heartbeat

Every 60 s the agent posts a `sensor.heartbeat` envelope. Two ways:

1. **Inline** — include in the next `/v1/events` batch.
2. **Dedicated** — `POST /v1/heartbeat` with one envelope. Useful when there are no threat events to piggyback on.

If the server hasn't seen a heartbeat in **6 minutes**, the sensor is marked `degraded`. In **1 hour**, `offline`. Operator-visible only; doesn't stop accepting their events when they return.

## Agent config pull

Every 15 min (± jitter) the agent calls `GET /v1/config` and receives:

```json
{
  "config_version": 42,
  "honeypots": {
    "ssh": { "enabled": true, "port": 2222, "depth": "medium" },
    "tls": { "enabled": true, "ports": [443, 8443], "sni_capture": true },
    "http": { "enabled": true, "port": 8080, "lures": ["wordpress", "phpmyadmin"] }
  },
  "sampling": {
    "scan.probe": 0.1
  },
  "telemetry": {
    "heartbeat_seconds": 60,
    "config_poll_seconds": 900
  }
}
```

This lets us:
- Toggle a flaky honeypot fleet-wide without touching sensors.
- Reduce noise from scanner floods by sampling `scan.probe`.
- Experiment with new honeypot modules on a subset of sensors via the config fetcher.

## Errors (standard across endpoints)

| Status | Body code | Meaning | Agent action |
|---|---|---|---|
| 400 | `malformed_batch` | Schema validation failed. | Log, discard, report at next heartbeat. |
| 401 | `auth_invalid` | Cert rejected. | Halt, surface to operator. |
| 403 | `sensor_revoked` | Cert valid but sensor banned. | Halt permanently. |
| 409 | `duplicate_event_id` | Event already accepted. | Treat as success. |
| 413 | `payload_too_large` | Batch too big. | Split and retry. |
| 429 | `rate_limited` | Throttled. | Retry after `Retry-After`. |
| 500 | `internal_error` | Ingest bug. | Retry with backoff. |
| 503 | `unavailable` | Planned maintenance. | Retry with backoff. |

## Security posture

- All transport: TLS 1.3 only. Earlier versions rejected at the edge.
- mTLS: required for every request except `/v1/enroll` (bearer-token).
- Agent never accepts inbound connections from ingest. Purely outbound-push.
- Config pull is GET-only; no server-side commands executed on sensors. (If we want remote agent actions later, that's a separate, signed, bidirectional protocol — NOT bolted onto this one.)

## Observability

Each envelope response includes:
- `X-Ingest-Build` — build tag of the receiving ingest node
- `X-Ingest-Latency-Ms` — time spent in ingest
- `X-Correlation-Id` — echoed if the batch included one, else generated

Agent logs the correlation ID alongside the batch ID for end-to-end tracing during incident response.
