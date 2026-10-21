import { NextResponse } from "next/server";
import { handler, errors } from "@/lib/http";
import { getInstance } from "@/lib/auth/instance";
import { issuerFor } from "@/lib/auth/keys";

/** Minimal discovery doc so standard JWT libraries can find the JWKS from the issuer. */
export const GET = handler(async (_req: Request, { params }: { params: Promise<{ instanceId: string }> }) => {
  const { instanceId } = await params;
  if (!(await getInstance(instanceId))) throw errors.notFound();
  const iss = issuerFor(instanceId);
  return NextResponse.json(
    { issuer: iss, jwks_uri: `${iss}/.well-known/jwks.json`, id_token_signing_alg_values_supported: ["ES256"] },
    { headers: { "cache-control": "public, max-age=300", "access-control-allow-origin": "*" } },
  );
});
