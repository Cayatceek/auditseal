package dev.cayatceek.auditseal;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class AuditVerifierTest {
    private static byte[] bytes(String value) { return value.getBytes(StandardCharsets.UTF_8); }

    @Test
    void verifiesValidChainWithExternalHead() {
        byte[] key = AuditTrail.generateKey();
        var trail = new AuditTrail(key);
        trail.append(Instant.parse("2026-11-01T10:00:00Z"), "alice", "TRANSFER", bytes("100"));
        trail.append(Instant.parse("2026-11-01T10:01:00Z"), "bob", "APPROVE", bytes("ok"));
        assertTrue(AuditVerifier.verify(trail.snapshot(), key, trail.headMac()).valid());
    }

    @Test
    void detectsModifiedEntry() {
        byte[] key = AuditTrail.generateKey();
        var trail = new AuditTrail(key);
        AuditEvent first = trail.append(Instant.now(), "alice", "CREATE", bytes("x"));
        AuditEvent forged = new AuditEvent(first.sequence(), first.occurredAt(), "mallory", first.action(),
            first.payloadSha256(), first.previousMac(), first.mac());
        var verification = AuditVerifier.verify(List.of(forged), key, trail.headMac());
        assertFalse(verification.valid());
        assertEquals(1, verification.failedSequence());
    }

    @Test
    void detectsMissingMiddleAndTailEntries() {
        byte[] key = AuditTrail.generateKey();
        var trail = new AuditTrail(key);
        for (int i = 0; i < 3; i++) trail.append(Instant.now(), "alice", "WRITE", bytes("" + i));
        List<AuditEvent> removedMiddle = new ArrayList<>(trail.snapshot());
        removedMiddle.remove(1);
        assertFalse(AuditVerifier.verify(removedMiddle, key, trail.headMac()).valid());
        List<AuditEvent> truncated = trail.snapshot().subList(0, 2);
        assertTrue(AuditVerifier.verify(truncated, key, null).valid()); // Cannot detect truncation without an anchor.
        assertFalse(AuditVerifier.verify(truncated, key, trail.headMac()).valid());
    }

    @Test
    void detectsAlteredExternalPayloadEvenWhenMetadataChainIsValid() {
        byte[] key = AuditTrail.generateKey();
        var trail = new AuditTrail(key);
        AuditEvent event = trail.append(Instant.now(), "alice", "TRANSFER", bytes("amount=100"));
        assertTrue(AuditVerifier.verify(trail.snapshot(), key, trail.headMac()).valid());
        assertTrue(AuditVerifier.verifyPayload(event, bytes("amount=100")));
        assertFalse(AuditVerifier.verifyPayload(event, bytes("amount=900")));
        assertThrows(NullPointerException.class, () -> AuditVerifier.verifyPayload(event, null));
    }

    @Test
    void protectsSecretAgainstCallerModifyingOriginalKeyArray() {
        byte[] key = AuditTrail.generateKey();
        byte[] originalKey = key.clone();
        AuditTrail trail = new AuditTrail(key);
        java.util.Arrays.fill(key, (byte) 0);
        trail.append(Instant.now(), "bob", "UPDATE", bytes("data"));
        assertTrue(AuditVerifier.verify(trail.snapshot(), originalKey, trail.headMac()).valid());
    }

    @Test
    void rejectsWrongKeyAndShortSecrets() {
        byte[] key = AuditTrail.generateKey();
        var trail = new AuditTrail(key);
        trail.append(Instant.now(), "alice", "CREATE", bytes("ok"));
        assertFalse(AuditVerifier.verify(trail.snapshot(), AuditTrail.generateKey(), trail.headMac()).valid());
        assertThrows(IllegalArgumentException.class, () -> new AuditTrail(new byte[3]));
    }

    @Test
    void lengthPrefixedEncodingPreventsFieldBoundaryAmbiguity() {
        byte[] key = AuditTrail.generateKey();
        var first = new AuditTrail(key);
        var second = new AuditTrail(key);
        Instant at = Instant.parse("2026-01-01T00:00:00Z");
        first.append(at, "a|b", "c", bytes("data"));
        second.append(at, "a", "b|c", bytes("data"));
        assertNotEquals(first.headMac(), second.headMac());
    }
}
