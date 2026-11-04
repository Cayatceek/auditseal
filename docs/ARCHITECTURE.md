# AuditSeal integrity format v1

Each authenticated event includes: version, monotonically increasing sequence, epoch-second and nanosecond timestamp, actor, action, SHA-256 hash of payload bytes, previous event HMAC and current HMAC.

Fields use length-prefixed UTF-8 encoding; cryptographic MAC uses HMAC-SHA-256. In-memory records do not include original payload bytes. Secret keys are defensively copied on creation. `AuditVerifier.verifyPayload(event, bytes)` separately checks payloads stored outside the chain. The chain alone authenticates only their recorded digests.

The genesis MAC is 32 zero bytes represented by 64 hexadecimal characters. A verifier rejects sequence gaps, incorrect previous tags, forged record tags and optional trusted-head mismatches.

## Security boundaries

For real deployment, keep the HMAC key outside the audit database, and pin the head with a separate trusted party or immutable storage. Persist events with durable ordering before updating the anchor. Single-writer and concurrency-safe persistence are future tasks. Merely linking hashes (or storing the anchor alongside data) is not sufficient to protect against an administrator rewriting all entries.
