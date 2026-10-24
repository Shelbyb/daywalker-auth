import { NextResponse } from "next/server";
import { handler, errors } from "@/lib/http";
import { getInstance } from "@/lib/auth/instance";
import { issuerFor } from "@/lib/auth/keys";
import { env } from "@/lib/env";

/** Minimal discovery doc so standard JWT libraries can find the JWKS from the issuer. */
export const GET = handler(async (_req: Request, { params }: { params: Promise<{ instanceId: string }> }) => {
  const { instanceId } = await params;
  if (!(await getInstance(instanceId))) throw errors.notFound();
  const iss = issuerFor(instanceId);
  return NextResponse.json(
    { issuer: iss, jwks_uri: `${iss}/.well-known/jwks.json`, id_token_signing_alg_values_supported: ["ES256"], token_endpoint: `${env().APP_URL}/v1/m2m/token`, token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"], grant_types_supported: ["client_credentials"] },
    { headers: { "cache-control": "public, max-age=300", "access-control-allow-origin": "*" } },
  );
});
