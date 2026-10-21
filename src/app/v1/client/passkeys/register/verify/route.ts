import { z } from "zod";
import type { RegistrationResponseJSON } from "@simplewebauthn/server";
import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { requireFreshSession } from "@/lib/auth/require-session";
import { verifyRegistration } from "@/lib/auth/passkeys";
import { readCredential } from "@/lib/auth/webauthn-input";

export const OPTIONS = preflight;

/** Step 2: the browser's attestation. Stores the public key. */
export const POST = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  const s = await requireFreshSession(ctx.inst, ctx.refreshToken);
  const body = await readCredential<RegistrationResponseJSON>(req, { name: z.string().max(60).optional() });
  const id = await verifyRegistration(ctx.inst, s.userId, s.id, body.response, body.name as string | undefined);
  return ctx.json({ id }, { status: 201 });
});
