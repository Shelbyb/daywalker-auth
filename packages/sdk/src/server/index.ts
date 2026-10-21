import { createRemoteJWKSet, jwtVerify, errors as joseErrors } from "jose";
import { instanceIdFromKey, issuerFor, type Config } from "../core/keys";

if (typeof window !== "undefined") {
  // Secret keys must never reach a browser bundle.
  throw new Error("@daywalker/auth/server must only be imported on the server");
}

export type SessionClaims = { userId: string; sessionId: string; issuedAt: number; expiresAt: number; azp?: string; orgId?: string; orgRole?: "admin" | "member" };

const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

export type VerifyOptions = Config & {
  /**
   * Origins allowed to have minted the token (checked against the `azp` claim). Recommended:
   * stops a token issued to another app on the same instance from being replayed against yours.
   */
  authorizedParties?: string[];
};

/**
 * Verifies a session JWT locally against the instance's JWKS (fetched once, then cached;
 * refetched automatically when an unknown `kid` appears after key rotation).
 * Returns null for any invalid, expired or foreign token. Never throws on bad input.
 */
export async function verifyToken(token: string | null | undefined, opts: VerifyOptions): Promise<SessionClaims | null> {
  if (!token) return null;
  const issuer = issuerFor(opts.frontendApi, instanceIdFromKey(opts.publishableKey));
  let jwks = jwksCache.get(issuer);
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(`${issuer}/.well-known/jwks.json`), { cooldownDuration: 30_000, cacheMaxAge: 600_000 });
    jwksCache.set(issuer, jwks);
  }
  try {
    const { payload } = await jwtVerify(token, jwks, {
      issuer,
      algorithms: ["ES256"], // pin the algorithm: never accept "none" or HS* confusion
      clockTolerance: 5,
      requiredClaims: ["sub", "sid", "exp", "iat"],
    });
    const azp = typeof payload.azp === "string" ? payload.azp : undefined;
    if (opts.authorizedParties?.length && azp && !opts.authorizedParties.includes(azp)) return null;
    const orgId = typeof payload.org_id === "string" ? payload.org_id : undefined;
    const orgRole = payload.org_role === "admin" || payload.org_role === "member" ? payload.org_role : undefined;
    return { userId: payload.sub!, sessionId: payload.sid as string, issuedAt: payload.iat!, expiresAt: payload.exp!, azp, orgId, orgRole };
  } catch (e) {
    if (e instanceof joseErrors.JOSEError) return null;
    throw e; // network/JWKS outages surface instead of looking like "signed out"
  }
}

export type BackendUser = {
  id: string;
  firstName: string | null;
  lastName: string | null;
  imageUrl: string | null;
  emailAddresses: { id: string; email: string; primary: boolean; verified: boolean }[];
  publicMetadata: Record<string, unknown>;
  privateMetadata: Record<string, unknown>;
  banned: boolean;
  lastSignInAt: string | null;
  createdAt: string;
};

export class BackendError extends Error {
  constructor(public status: number, public code: string, message: string) {
    super(message);
    this.name = "BackendError";
  }
}

/** Client for the backend API. Requires your secret key (sk_...); keep it in server env only. */
export function createBackendClient(opts: { secretKey: string; apiUrl: string }) {
  if (!/^sk_(test|live)_/.test(opts.secretKey)) throw new Error("createBackendClient needs a secret key (sk_...)");
  const base = new URL(opts.apiUrl).origin;

  async function call<T>(method: string, path: string): Promise<T> {
    const res = await fetch(`${base}/v1/${path}`, {
      method,
      headers: { authorization: `Bearer ${opts.secretKey}` },
      cache: "no-store",
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new BackendError(res.status, body.error?.code ?? "unknown", body.error?.message ?? "Request failed");
    return body as T;
  }

  return {
    users: {
      list: (q: { limit?: number; offset?: number } = {}) =>
        call<{ data: BackendUser[] }>("GET", `users?limit=${q.limit ?? 20}&offset=${q.offset ?? 0}`).then((r) => r.data),
      get: (userId: string) => call<BackendUser>("GET", `users/${encodeURIComponent(userId)}`),
      delete: (userId: string) => call<{ id: string; deleted: true }>("DELETE", `users/${encodeURIComponent(userId)}`),
    },
    organizations: {
      list: (q: { limit?: number; offset?: number } = {}) =>
        call<{ data: { id: string; name: string; slug: string; createdAt: string }[] }>(
          "GET",
          `organizations?limit=${q.limit ?? 20}&offset=${q.offset ?? 0}`,
        ).then((r) => r.data),
      members: (orgId: string) =>
        call<{ data: { userId: string; role: "admin" | "member"; joinedAt: string }[] }>(
          "GET",
          `organizations/${encodeURIComponent(orgId)}/members`,
        ).then((r) => r.data),
    },
    sessions: {
      revoke: (sessionId: string) => call<{ id: string; status: "revoked" }>("POST", `sessions/${encodeURIComponent(sessionId)}/revoke`),
    },
  };
}
