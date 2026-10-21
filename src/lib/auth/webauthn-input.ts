import { z } from "zod";
import { errors } from "../http";

/**
 * Shape check for credentials posted by the browser. Full cryptographic verification
 * happens in the WebAuthn library; this just rejects junk and oversized bodies early.
 */
const credential = z
  .object({
    id: z.string().min(1).max(1024),
    rawId: z.string().min(1).max(1024),
    type: z.literal("public-key"),
    response: z.record(z.string(), z.unknown()),
    clientExtensionResults: z.record(z.string(), z.unknown()).default({}),
    authenticatorAttachment: z.string().optional(),
  })
  .passthrough();

export async function readCredential<T>(req: Request, extra: z.ZodRawShape = {}) {
  const len = Number(req.headers.get("content-length") ?? 0);
  if (len > 64 * 1024) throw errors.badRequest("payload_too_large", "Request body is too large");
  const body = z.object({ response: credential, ...extra }).parse(await req.json());
  return body as { response: T } & Record<string, unknown>;
}
