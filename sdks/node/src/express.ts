import { Request, Response, NextFunction } from "express";
import { ZTNAGatewayVerifier, ZTNAContext, ZTNAVerifierOptions } from "./verifier";

declare global {
  namespace Express {
    interface Request {
      ztna?: ZTNAContext;
    }
  }
}

export function ztnaExpressMiddleware(
  options: ZTNAVerifierOptions & { enforce?: boolean }
) {
  const verifier = new ZTNAGatewayVerifier(options);
  const enforce = options.enforce ?? true;

  return (req: Request, res: Response, next: NextFunction) => {
    try {
      req.ztna = verifier.verifyHeaders(req.headers);
      next();
    } catch (err: any) {
      if (enforce) {
        return res.status(403).json({
          error: "ztna_verification_failed",
          detail: err.message || "Zero Trust verification failed",
        });
      }
      req.ztna = undefined;
      next();
    }
  };
}
