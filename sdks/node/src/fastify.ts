import { ZTNAGatewayVerifier, ZTNAContext, ZTNAVerifierOptions } from "./verifier";

export function ztnaFastifyPlugin(
  options: ZTNAVerifierOptions & { enforce?: boolean }
) {
  const verifier = new ZTNAGatewayVerifier(options);
  const enforce = options.enforce ?? true;

  return async function (fastify: any) {
    fastify.decorateRequest("ztna", null);

    fastify.addHook("onRequest", async (request: any, reply: any) => {
      try {
        request.ztna = verifier.verifyHeaders(request.headers);
      } catch (err: any) {
        if (enforce) {
          reply.code(403).send({
            error: "ztna_verification_failed",
            detail: err.message || "Zero Trust verification failed",
          });
        }
      }
    });
  };
}
