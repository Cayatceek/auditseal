package dev.cayatceek.auditseal;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.HexFormat;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Canonical length-prefixed encoding, versioned for future format changes. */
final class AuditCrypto {
    static final String GENESIS = "0".repeat(64);
    private static final HexFormat HEX = HexFormat.of();

    private AuditCrypto() { }

    static byte[] digest(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("SHA-256 is unavailable", ex);
        }
    }

    static String sha256(byte[] data) {
        return HEX.formatHex(digest(data));
    }

    static String mac(byte[] key, long sequence, java.time.Instant at,
                      String actor, String action, String payloadHash, String previous) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return HEX.formatHex(mac.doFinal(encode(sequence, at, actor, action, payloadHash, previous)));
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("HmacSHA256 is unavailable", ex);
        }
    }

    static boolean equalMac(String expected, String actual) {
        return MessageDigest.isEqual(expected.getBytes(StandardCharsets.US_ASCII),
            actual.getBytes(StandardCharsets.US_ASCII));
    }

    private static byte[] encode(long sequence, java.time.Instant at, String actor,
                                 String action, String payloadHash, String previous) {
        try {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            DataOutputStream out = new DataOutputStream(buffer);
            out.writeUTF("auditseal-v1");
            out.writeLong(sequence);
            out.writeLong(at.getEpochSecond());
            out.writeInt(at.getNano());
            write(out, actor);
            write(out, action);
            write(out, payloadHash);
            write(out, previous);
            out.flush();
            return buffer.toByteArray();
        } catch (IOException ex) {
            throw new IllegalStateException("Unexpected in-memory encoding failure", ex);
        }
    }

    private static void write(DataOutputStream out, String value) throws IOException {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        out.writeInt(bytes.length);
        out.write(bytes);
    }
}
