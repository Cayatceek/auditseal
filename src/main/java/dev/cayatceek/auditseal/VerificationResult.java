package dev.cayatceek.auditseal;

/** No failure details are dependent on sensitive event payloads. */
public record VerificationResult(boolean valid, long failedSequence, String reason) {
    public static VerificationResult ok() { return new VerificationResult(true, -1, "OK"); }
    public static VerificationResult failure(long index, String reason) {
        return new VerificationResult(false, index, reason);
    }
}
