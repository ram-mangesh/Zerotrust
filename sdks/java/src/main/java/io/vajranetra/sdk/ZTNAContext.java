package io.vajranetra.sdk;

public class ZTNAContext {
    private final String userId;
    private final String email;
    private final String role;
    private final double trustScore;
    private final String riskLevel;
    private final long timestamp;
    private final String requestId;

    public ZTNAContext(String userId, String email, String role, double trustScore, String riskLevel, long timestamp, String requestId) {
        this.userId = userId;
        this.email = email;
        this.role = role;
        this.trustScore = trustScore;
        this.riskLevel = riskLevel;
        this.timestamp = timestamp;
        this.requestId = requestId;
    }

    public String getUserId() { return userId; }
    public String getEmail() { return email; }
    public String getRole() { return role; }
    public double getTrustScore() { return trustScore; }
    public String getRiskLevel() { return riskLevel; }
    public long getTimestamp() { return timestamp; }
    public String getRequestId() { return requestId; }
}
