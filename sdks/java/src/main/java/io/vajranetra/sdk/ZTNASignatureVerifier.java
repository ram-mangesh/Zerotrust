package io.vajranetra.sdk;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;
import java.util.Map;

public class ZTNASignatureVerifier {
    private final byte[] secretKey;
    private final long maxAgeSeconds;
    private final double minTrustScore;

    public ZTNASignatureVerifier(String secretKey, long maxAgeSeconds, double minTrustScore) {
        if (secretKey == null || secretKey.isEmpty()) {
            throw new IllegalArgumentException("secretKey must not be empty");
        }
        this.secretKey = secretKey.getBytes(StandardCharsets.UTF_8);
        this.maxAgeSeconds = maxAgeSeconds;
        this.minTrustScore = minTrustScore;
    }

    public ZTNASignatureVerifier(String secretKey) {
        this(secretKey, 60, 0.0);
    }

    public ZTNAContext verifyHeaders(Map<String, String> headers) throws Exception {
        String userId = headers.get("x-forwarded-user");
        String email = headers.getOrDefault("x-forwarded-email", "");
        String role = headers.getOrDefault("x-forwarded-role", "guest");
        String trustStr = headers.get("x-ztna-trust-score");
        String riskLevel = headers.getOrDefault("x-ztna-risk-level", "LOW");
        String sig = headers.get("x-gateway-signature");
        String tsStr = headers.get("x-gateway-timestamp");
        String requestId = headers.get("x-request-id");

        if (userId == null || sig == null || tsStr == null || trustStr == null) {
            throw new SecurityException("Missing mandatory VajraNetra ZTNA gateway headers");
        }

        long ts = Long.parseLong(tsStr);
        double trustScore = Double.parseDouble(trustStr);

        long now = System.currentTimeMillis() / 1000L;
        if (Math.abs(now - ts) > maxAgeSeconds) {
            throw new SecurityException("Gateway signature expired (timestamp delta > " + maxAgeSeconds + "s)");
        }

        String payload = String.format(Locale.US, "%s:%s:%.2f:%s", userId, role, trustScore, tsStr);
        Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(new SecretKeySpec(secretKey, "HmacSHA256"));
        byte[] hash = hmac.doFinal(payload.getBytes(StandardCharsets.UTF_8));

        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        String expectedSig = hexString.toString();

        if (!MessageDigest.isEqual(expectedSig.getBytes(StandardCharsets.UTF_8), sig.getBytes(StandardCharsets.UTF_8))) {
            throw new SecurityException("Invalid gateway HMAC signature: request forged or modified");
        }

        if (trustScore < minTrustScore) {
            throw new SecurityException("Trust score (" + trustScore + ") below required minimum (" + minTrustScore + ")");
        }

        return new ZTNAContext(userId, email, role, trustScore, riskLevel, ts, requestId);
    }
}
