/**
 * Session binding to a device key (DPoP, RFC 9449). The browser SDK makes a non-extractable ECDSA
 * P-256 key; every request then carries a short-lived proof JWT signed with it in the `DPoP` header.
 * A session created with a proof is tied to that key's thumbprint, so a stolen refresh cookie is
 * useless without the key. See lib/auth/sessions.ts for where this is enforced.
 *
 * Only ES256 is accepted, the key must be a public EC P-256 JWK, and each proof is single use
 * (jti kept in Valkey for the freshness window). No server nonce: replay is bounded by `iat` and `jti`.
 */
import { calculateJwkThumbprint, decodeProtectedHeader, importJWK, jwtVerify, type JWK } from "jose";
import { cache } from "../cache";
import { env } from "../env";
import { ApiError } from "../http";
import { sha256 } from "../ids";

export const DEVICE_BINDING_MODES = ["off", "optional", "required"] as const;
export type DeviceBindingMode = (typeof DEVICE_BINDING_MODES)[number];

/** Proofs older or newer than this (seconds) are refused. */
export const PROOF_SKEW_SECONDS = 60;
const MAX_PROOF_BYTES = 4096;

const invalid = (why: string) => new ApiError(401, "invalid_dpop_proof", `Invalid DPoP proof: ${why}`);

/** The raw proof from the request, or null when the header is absent. Rejects repeated headers. */
export function proofHeader(req: Request): string | null {
  const v = req.headers.get("dpop");
  if (v === null) return null;
  if (v.includes(",") || v.length > MAX_PROOF_BYTES || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(v)) throw invalid("malformed");
  return v;
}

/** The URL a proof must name: the service's own origin plus the request path (no query or fragment). */
export function expectedHtu(req: Request) {
  return `${new URL(env().APP_URL).origin}${new URL(req.url).pathname}`;
}

/**
 * Verifies a proof for this request and returns the key's thumbprint. Throws 401 `invalid_dpop_proof`
 * for anything wrong; a proof is accepted once.
 */
export async function verifyProof(req: Request, instanceId: string, proof: string): Promise<{ jkt: string }> {
  let header;
  try {
    header = decodeProtectedHeader(proof);
  } catch {
    throw invalid("malformed");
  }
  if (header.typ !== "dpop+jwt") throw invalid("typ must be dpop+jwt");
  if (header.alg !== "ES256") throw invalid("alg must be ES256");
  const jwk = header.jwk as JWK | undefined;
  if (!jwk || jwk.kty !== "EC" || jwk.crv !== "P-256" || typeof jwk.x !== "string" || typeof jwk.y !== "string") throw invalid("jwk must be an EC P-256 public key");
  if ("d" in jwk) throw invalid("jwk must not contain a private key");
  const publicJwk: JWK = { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y };
  let payload;
  try {
    const key = await importJWK(publicJwk, "ES256");
    ({ payload } = await jwtVerify(proof, key, { algorithms: ["ES256"], typ: "dpop+jwt", clockTolerance: PROOF_SKEW_SECONDS, requiredClaims: ["jti", "iat"] }));
  } catch {
    throw invalid("signature or claims");
  }
  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.iat !== "number" || Math.abs(now - payload.iat) > PROOF_SKEW_SECONDS) throw invalid("iat out of range");
  if (typeof payload.jti !== "string" || payload.jti.length < 8 || payload.jti.length > 200) throw invalid("jti");
  if (payload.htm !== req.method) throw invalid("htm does not match the request method");
  if (payload.htu !== expectedHtu(req)) throw invalid("htu does not match the request URL");
  const jkt = await calculateJwkThumbprint(publicJwk, "sha256");
  // Single use: the same proof can't be replayed within its freshness window.
  const fresh = await cache().set(`dpop:${instanceId}:${sha256(`${jkt}.${payload.jti}`)}`, "1", "EX", PROOF_SKEW_SECONDS * 2 + 5, "NX");
  if (!fresh) throw invalid("proof already used");
  return { jkt };
}

const verified = new WeakMap<Request, Promise<{ jkt: string } | null>>();

/**
 * The key proven by this request's DPoP header, or null when there is no header. Memoized per request:
 * a sign-in verifies the proof when it creates the session and again when it mints the first token,
 * and a proof may be used only once.
 */
export function requestProof(req: Request, instanceId: string) {
  let p = verified.get(req);
  if (!p) {
    const raw = proofHeader(req);
    p = raw ? verifyProof(req, instanceId, raw) : Promise.resolve(null);
    verified.set(req, p);
  }
  return p;
}
