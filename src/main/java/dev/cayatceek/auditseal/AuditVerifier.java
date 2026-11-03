package dev.cayatceek.auditseal;

import java.util.List;
import java.util.Objects;

/** Verifies the chain, sequence and optional trusted head MAC. */
public final class AuditVerifier {
    private AuditVerifier() { }

    public static VerificationResult verify(List<AuditEvent> events, byte[] secretKey, String trustedHead) {
        Objects.requireNonNull(events, "events");
        Objects.requireNonNull(secretKey, "secretKey");
        if (secretKey.length < 32) throw new IllegalArgumentException("Key must be at least 32 bytes");
        String previous = AuditCrypto.GENESIS;
        for (int i = 0; i < events.size(); i++) {
            AuditEvent event = Objects.requireNonNull(events.get(i), "event");
            long expectedSequence = i + 1L;
            if (event.sequence() != expectedSequence) {
                return VerificationResult.failure(expectedSequence, "Non-contiguous sequence");
            }
            if (!AuditCrypto.equalMac(previous, event.previousMac())) {
                return VerificationResult.failure(expectedSequence, "Previous MAC mismatch");
            }
            String calculated = AuditCrypto.mac(secretKey, event.sequence(), event.occurredAt(),
                event.actor(), event.action(), event.payloadSha256(), event.previousMac());
            if (!AuditCrypto.equalMac(calculated, event.mac())) {
                return VerificationResult.failure(expectedSequence, "Invalid HMAC");
            }
            previous = event.mac();
        }
        if (trustedHead != null && !AuditCrypto.equalMac(previous, trustedHead)) {
            return VerificationResult.failure(events.size() + 1L, "Trusted head mismatch / truncated log");
        }
        return VerificationResult.ok();
    }
}
