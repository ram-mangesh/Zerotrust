import * as crypto from "crypto";

export interface ZTNAContext {
  userId: string;
  email: string;
  role: string;
  trustScore: number;
  riskLevel: string;
  timestamp: number;
  requestId?: string;
}

export interface ZTNAVerifierOptions {
  secretKey: string;
  maxAgeSeconds?: number;
  minTrustScore?: number;
}

export class ZTNAGatewayVerifier {
  private readonly secretKey: Buffer;
  private readonly maxAgeSeconds: number;
  private readonly minTrustScore: number;

  constructor(options: ZTNAVerifierOptions) {
    if (!options.secretKey) {
      throw new Error("VajraNetra SDK: secretKey must not be empty");
    }
    this.secretKey = Buffer.from(options.secretKey, "utf-8");
    this.maxAgeSeconds = options.maxAgeSeconds ?? 60;
    this.minTrustScore = options.minTrustScore ?? 0;
  }

  /**
   * Verifies incoming HTTP request headers and returns validated ZTNA context.
   */
  public verifyHeaders(headers: Record<string, string | string[] | undefined>): ZTNAContext {
    const h: Record<string, string> = {};
    for (const [key, val] of Object.entries(headers)) {
      if (typeof val === "string") {
        h[key.toLowerCase()] = val;
      } else if (Array.isArray(val) && val.length > 0) {
        h[key.toLowerCase()] = val[0];
      }
    }

    const userId = h["x-forwarded-user"];
    const email = h["x-forwarded-email"] || "";
    const role = h["x-forwarded-role"] || "guest";
    const trustStr = h["x-ztna-trust-score"];
    const riskLevel = h["x-ztna-risk-level"] || "LOW";
    const sig = h["x-gateway-signature"];
    const tsStr = h["x-gateway-timestamp"];
    const requestId = h["x-request-id"];

    if (!userId || !sig || !tsStr || !trustStr) {
      throw new Error("Missing required VajraNetra ZTNA gateway headers");
    }

    const ts = parseInt(tsStr, 10);
    const trustScore = parseFloat(trustStr);

    if (isNaN(ts) || isNaN(trustScore)) {
      throw new Error("Malformed timestamp or trust score header from gateway");
    }

    // Check anti-replay expiration
    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - ts) > this.maxAgeSeconds) {
      throw new Error(`Gateway signature expired (timestamp delta > ${this.maxAgeSeconds}s)`);
    }

    // Verify HMAC-SHA256 signature
    const payload = `${userId}:${role}:${trustScore.toFixed(2)}:${tsStr}`;
    const expectedSig = crypto
      .createHmac("sha256", this.secretKey)
      .update(payload)
      .digest("hex");

    const expectedBuf = Buffer.from(expectedSig, "utf-8");
    const actualBuf = Buffer.from(sig, "utf-8");

    if (
      expectedBuf.length !== actualBuf.length ||
      !crypto.timingSafeEqual(expectedBuf, actualBuf)
    ) {
      throw new Error("Invalid gateway HMAC signature: request forged or modified");
    }

    if (trustScore < this.minTrustScore) {
      throw new Error(`Trust score (${trustScore}) below required threshold (${this.minTrustScore})`);
    }

    return {
      userId,
      email,
      role,
      trustScore,
      riskLevel,
      timestamp: ts,
      requestId,
    };
  }
}
