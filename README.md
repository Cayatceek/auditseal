# AuditSeal

Tamper-evident audit journaling for Java applications. AuditSeal combines a **SHA-256 payload digest**, an **HMAC-SHA-256 authenticated chain**, and an optional **externally pinned head MAC**.

**Status:** 0.1.0-SNAPSHOT. This is a development library, not a compliance-certified storage product. Java 21, zero runtime dependencies.

## Example

```java
// Generate a secret ONCE and store it in a secure secret manager, not in Git.
byte[] key = loadKeyFromKms();
AuditTrail trail = new AuditTrail(key);

AuditEvent event = trail.append(
    Instant.now(), "staff-12", "LIMIT_CHANGED", jsonBytes);

// Persist this event DURABLY, then pin the latest head MAC outside that database.
String trustedHead = trail.headMac();
VerificationResult result = AuditVerifier.verify(loadStoredEvents(), key, trustedHead);
if (!result.valid()) throw new SecurityException(result.reason());
```

`AuditTrail.generateKey()` generates a fresh random key, useful for development. **Never generate a new key on each application restart for a persistent audit log.**

## Threat model

- Detects modifications, insertions, reordering and middle deletions when the verifier has the original secret key.
- With a separately trusted `headMac`, also detects tail truncation.
- A database administrator who cannot read the HMAC key cannot forge a valid chain of altered entries.
- If the attacker obtains the HMAC key **and** can modify the trusted anchor, or the app accepts untrusted anchors, this scheme is not tamper-resistant.
- Payloads are **not stored**. The event records a digest; verification of original payloads requires separately storing them and comparing their hashes.

## Limitations

The current trail is **in-memory**. Crash safety, persistent storage, atomic anchor updates, distributed writers, key rotation and integration with Spring Security are not implemented. Do not advertise this release as a complete compliance or forensic log system.

## Development

```bash
mvn verify
mvn install
```

GPL-3.0, see LICENSE. See [architecture](docs/ARCHITECTURE.md) and [roadmap](docs/ROADMAP.md).
