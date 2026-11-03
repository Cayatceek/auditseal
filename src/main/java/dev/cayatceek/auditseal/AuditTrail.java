package dev.cayatceek.auditseal;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * In-memory audit log writer. Store events durably and pin the head MAC outside the
 * event database to detect truncation. Key material must be held separately.
 */
public final class AuditTrail {
    private final byte[] key;
    private final List<AuditEvent> events = new ArrayList<>();

    public AuditTrail(byte[] secretKey) {
        Objects.requireNonNull(secretKey, "secretKey");
        if (secretKey.length < 32) {
            throw new IllegalArgumentException("Use a cryptographically random secret key of at least 32 bytes");
        }
        this.key = secretKey.clone();
    }

    public static byte[] generateKey() {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        return key;
    }

    public synchronized AuditEvent append(Instant when, String actor, String action, byte[] payload) {
        Objects.requireNonNull(when, "when");
        Objects.requireNonNull(payload, "payload");
        long sequence = events.size() + 1L;
        String previous = headMac();
        String payloadHash = AuditCrypto.sha256(payload);
        String tag = AuditCrypto.mac(key, sequence, when, actor, action, payloadHash, previous);
        AuditEvent event = new AuditEvent(sequence, when, actor, action, payloadHash, previous, tag);
        events.add(event);
        return event;
    }

    public synchronized List<AuditEvent> snapshot() { return List.copyOf(events); }

    /** Record this value in a separately trusted location after durable persistence. */
    public synchronized String headMac() {
        return events.isEmpty() ? AuditCrypto.GENESIS : events.getLast().mac();
    }
}
