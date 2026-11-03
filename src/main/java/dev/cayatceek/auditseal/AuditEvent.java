package dev.cayatceek.auditseal;

import java.time.Instant;
import java.util.Objects;

/**
 * A tamper-evident metadata record. Payload bytes are not stored.
 * The MAC authenticates all fields, their ordering and the previous MAC.
 */
public record AuditEvent(
    long sequence,
    Instant occurredAt,
    String actor,
    String action,
    String payloadSha256,
    String previousMac,
    String mac
) {
    public AuditEvent {
        if (sequence < 1) throw new IllegalArgumentException("sequence must be positive");
        Objects.requireNonNull(occurredAt, "occurredAt");
        require(actor, "actor");
        require(action, "action");
        require(payloadSha256, "payloadSha256");
        require(previousMac, "previousMac");
        require(mac, "mac");
    }

    private static void require(String value, String name) {
        Objects.requireNonNull(value, name);
        if (value.isBlank()) throw new IllegalArgumentException(name + " cannot be blank");
    }
}
