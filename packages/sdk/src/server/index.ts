import { createHmac, timingSafeEqual } from "node:crypto";
import { createRemoteJWKSet, jwtVerify, errors as joseErrors } from "jose";
import { instanceIdFromKey, issuerFor, type Config } from "../core/keys";

if (typeof window !== "undefined") {
  // Secret keys must never reach a browser bundle.
  throw new Error("@daywalker/auth/server must only be imported on the server");
}

export type SessionClaims = { userId: string; sessionId: string; issuedAt: number; expiresAt: number; azp?: string; orgId?: string; orgRole?: string; /** Permissions of `orgRole` in the active organization, e.g. "org:billing:manage". */ orgPermissions?: string[]; /** Custom claims set in the dashboard. */ claims?: Record<string, unknown> };

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
    const orgRole = typeof payload.org_role === "string" ? payload.org_role : undefined;
    const orgPermissions = Array.isArray(payload.org_permissions) ? payload.org_permissions.filter((p): p is string => typeof p === "string") : orgId ? [] : undefined;
    return { userId: payload.sub!, sessionId: payload.sid as string, issuedAt: payload.iat!, expiresAt: payload.exp!, azp, orgId, orgRole, orgPermissions, claims: customClaims(payload) };
  } catch (e) {
    if (e instanceof joseErrors.JOSEError) return null;
    throw e; // network/JWKS outages surface instead of looking like "signed out"
  }
}

/**
 * Does this session have what you ask for? Pass `{ permission }` (e.g. "org:billing:manage") and/or `{ role }`;
 * every key you pass must match. False without an active organization. Decide on the server: the token is signed,
 * so this can't be forged, while the same check in the browser is only for showing or hiding UI.
 */
export function has(claims: Pick<SessionClaims, "orgId" | "orgRole" | "orgPermissions"> | null | undefined, check: { permission?: string; role?: string }): boolean {
  if (!claims?.orgId || (check.permission === undefined && check.role === undefined)) return false;
  if (check.role !== undefined && claims.orgRole !== check.role) return false;
  if (check.permission !== undefined && !claims.orgPermissions?.includes(check.permission)) return false;
  return true;
}

/** Like `has`, but throws a `ForbiddenError` (status 403) when the check fails. Use it at the top of a route handler or server action. */
export class ForbiddenError extends Error {
  status = 403;
  constructor(message = "Forbidden") {
    super(message);
    this.name = "ForbiddenError";
  }
}
export function protect(claims: Pick<SessionClaims, "orgId" | "orgRole" | "orgPermissions"> | null | undefined, check: { permission?: string; role?: string }) {
  if (!has(claims, check)) throw new ForbiddenError(check.permission ? `Missing permission ${check.permission}` : "Forbidden");
}

export type WebhookEvent<T = Record<string, unknown>> = { id: string; type: string; createdAt: string; data: T };

export class WebhookVerificationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "WebhookVerificationError";
  }
}

/**
 * Verifies a webhook request and returns the parsed event. Pass the RAW request body
 * (`await req.text()`), not re-serialized JSON: the signature covers the exact bytes.
 * Throws WebhookVerificationError for a bad signature, a missing header, or a timestamp
 * outside the tolerance (default 5 minutes), which stops replayed requests.
 */
export function verifyWebhook<T = Record<string, unknown>>(
  rawBody: string,
  headers: Headers | Record<string, string | string[] | undefined>,
  secret: string,
  opts: { toleranceSeconds?: number } = {},
): WebhookEvent<T> {
  const get = (name: string) => {
    const v = headers instanceof Headers ? headers.get(name) : headers[name];
    return Array.isArray(v) ? v[0] : (v ?? null);
  };
  const id = get("webhook-id"), ts = get("webhook-timestamp"), sigHeader = get("webhook-signature");
  if (!id || !ts || !sigHeader) throw new WebhookVerificationError("Missing webhook headers");
  const seconds = Number(ts);
  if (!Number.isInteger(seconds)) throw new WebhookVerificationError("Invalid timestamp");
  if (Math.abs(Date.now() / 1000 - seconds) > (opts.toleranceSeconds ?? 300)) throw new WebhookVerificationError("Timestamp outside the allowed window");

  const key = Buffer.from(secret.replace(/^whsec_/, ""), "base64");
  const expected = createHmac("sha256", key).update(`${id}.${ts}.${rawBody}`).digest();
  // The header can hold several space-separated signatures (during secret rotation).
  const ok = sigHeader.split(" ").some((part) => {
    const [version, sig] = part.split(",");
    if (version !== "v1" || !sig) return false;
    const given = Buffer.from(sig, "base64");
    return given.length === expected.length && timingSafeEqual(given, expected);
  });
  if (!ok) throw new WebhookVerificationError("Signature doesn't match");
  try {
    return JSON.parse(rawBody) as WebhookEvent<T>;
  } catch {
    throw new WebhookVerificationError("Body isn't valid JSON");
  }
}

export type EmailTemplateKind = "verify_email" | "reset_password" | "sign_in" | "invitation";
export type EmailTemplate = {
  kind: EmailTemplateKind;
  subject: string;
  body: string;
  custom: boolean;
  placeholders?: string[];
  required?: string[];
  updatedAt: string | null;
};

export type AuditEvent = {
  id: string;
  type: string;
  actor: { type: "user" | "developer" | "api" | "system"; id: string | null };
  target: string | null;
  data: Record<string, unknown> | null;
  createdAt: string;
};

export type OrgRoleDef = { key: string; name: string; description: string | null; permissions: string[]; builtIn: boolean };
export type OrgDomainDef = {
  id: string; domain: string; verified: boolean; verifiedVia: "dns" | "email" | null; enrollment: "none" | "suggest" | "auto_join"; role: string | null; createdAt: string;
  dns?: { type: "TXT"; name: string; value: string };
};
export type WebhookEndpoint = { id: string; url: string; events: string[]; description: string | null; enabled: boolean; createdAt: string };
export type WebhookDelivery = {
  id: string; eventId: string; eventType: string; status: "pending" | "succeeded" | "failed"; attempts: number;
  lastStatusCode: number | null; lastError: string | null; nextAttemptAt: string | null; deliveredAt: string | null; createdAt: string;
};

export type BackendUser = {
  id: string;
  firstName: string | null;
  lastName: string | null;
  imageUrl: string | null;
  emailAddresses: { id: string; email: string; primary: boolean; verified: boolean }[];
  publicMetadata: Record<string, unknown>;
  privateMetadata: Record<string, unknown>;
  banned: boolean;
  /** ISO time the account is locked until after repeated failed attempts, or null. */
  lockedUntil: string | null;
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

  async function call<T>(method: string, path: string, json?: unknown): Promise<T> {
    const res = await fetch(`${base}/v1/${path}`, {
      method,
      headers: { authorization: `Bearer ${opts.secretKey}`, ...(json !== undefined ? { "content-type": "application/json" } : {}) },
      body: json === undefined ? undefined : JSON.stringify(json),
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
      /** Lifts a lockout and resets its progression. `unlocked` is false if the account wasn't locked. */
      unlock: (userId: string) => call<{ id: string; unlocked: boolean }>("POST", `users/${encodeURIComponent(userId)}/unlock`, {}),
    },
    organizations: {
      list: (q: { limit?: number; offset?: number } = {}) =>
        call<{ data: { id: string; name: string; slug: string; createdAt: string }[] }>(
          "GET",
          `organizations?limit=${q.limit ?? 20}&offset=${q.offset ?? 0}`,
        ).then((r) => r.data),
      members: (orgId: string) =>
        call<{ data: { userId: string; role: string; joinedAt: string }[] }>(
          "GET",
          `organizations/${encodeURIComponent(orgId)}/members`,
        ).then((r) => r.data),
    },
    organizationRoles: {
      list: () => call<{ data: OrgRoleDef[] }>("GET", "organization_roles").then((r) => r.data),
      get: (key: string) => call<OrgRoleDef>("GET", `organization_roles/${encodeURIComponent(key)}`),
      create: (input: { key: string; name: string; description?: string | null; permissions: string[] }) => call<OrgRoleDef>("POST", "organization_roles", input),
      update: (key: string, input: { name?: string; description?: string | null; permissions?: string[] }) => call<OrgRoleDef>("PATCH", `organization_roles/${encodeURIComponent(key)}`, input),
      /** Fails with `role_in_use` while members, invitations or settings still use it. */
      delete: (key: string) => call<{ key: string; deleted: true }>("DELETE", `organization_roles/${encodeURIComponent(key)}`),
    },
    organizationDomains: {
      list: (orgId: string) => call<{ data: OrgDomainDef[] }>("GET", `organizations/${encodeURIComponent(orgId)}/domains`).then((r) => r.data),
      add: (orgId: string, domain: string) => call<OrgDomainDef>("POST", `organizations/${encodeURIComponent(orgId)}/domains`, { domain }),
      verifyDns: (orgId: string, domainId: string) => call<OrgDomainDef>("POST", `organizations/${encodeURIComponent(orgId)}/domains/${encodeURIComponent(domainId)}/verify`, { method: "dns" }),
      sendEmail: (orgId: string, domainId: string, mailbox: string) => call<{ sentTo: string }>("POST", `organizations/${encodeURIComponent(orgId)}/domains/${encodeURIComponent(domainId)}/verify`, { method: "email", mailbox }),
      verifyEmail: (orgId: string, domainId: string, code: string) => call<OrgDomainDef>("POST", `organizations/${encodeURIComponent(orgId)}/domains/${encodeURIComponent(domainId)}/verify`, { method: "email", code }),
      update: (orgId: string, domainId: string, input: { enrollment?: "none" | "suggest" | "auto_join"; role?: string | null }) => call<OrgDomainDef>("PATCH", `organizations/${encodeURIComponent(orgId)}/domains/${encodeURIComponent(domainId)}`, input),
      remove: (orgId: string, domainId: string) => call<{ id: string; deleted: true }>("DELETE", `organizations/${encodeURIComponent(orgId)}/domains/${encodeURIComponent(domainId)}`),
    },
    emailTemplates: {
      list: () => call<{ data: EmailTemplate[]; accentColor: string | null }>("GET", "email_templates"),
      get: (kind: EmailTemplateKind) => call<EmailTemplate>("GET", `email_templates/${kind}`),
      /** Plain text with {{placeholders}}; HTML is built and escaped for you. */
      update: (kind: EmailTemplateKind, input: { subject: string; body: string }) => call<EmailTemplate>("PUT", `email_templates/${kind}`, input),
      /** Back to the built-in wording. */
      reset: (kind: EmailTemplateKind) => call<EmailTemplate>("DELETE", `email_templates/${kind}`),
      /** Button and link color, e.g. "#4f46e5". `null` restores the default. */
      setAccentColor: (accentColor: string | null) => call<{ accentColor: string | null }>("PUT", "email_templates/branding", { accentColor }),
    },
    auditEvents: {
      /** Newest first. Pass `before: page.nextCursor` for the next page. */
      list: (q: { type?: string; target?: string; before?: string; limit?: number } = {}) => {
        const p = new URLSearchParams();
        for (const [k, v] of Object.entries(q)) if (v !== undefined && v !== "") p.set(k, String(v));
        return call<{ data: AuditEvent[]; nextCursor: string | null }>("GET", `audit_events${p.size ? `?${p}` : ""}`);
      },
    },
    webhooks: {
      list: () => call<{ data: WebhookEndpoint[] }>("GET", "webhooks").then((r) => r.data),
      get: (id: string) => call<WebhookEndpoint>("GET", `webhooks/${encodeURIComponent(id)}`),
      /** The returned `secret` is shown only once. Store it as an environment variable. */
      create: (input: { url: string; events?: string[]; description?: string }) =>
        call<WebhookEndpoint & { secret: string }>("POST", "webhooks", input),
      update: (id: string, input: { url?: string; events?: string[]; description?: string | null; enabled?: boolean }) =>
        call<WebhookEndpoint>("PATCH", `webhooks/${encodeURIComponent(id)}`, input),
      delete: (id: string) => call<{ id: string; deleted: true }>("DELETE", `webhooks/${encodeURIComponent(id)}`),
      rotateSecret: (id: string) => call<{ id: string; secret: string }>("POST", `webhooks/${encodeURIComponent(id)}/rotate_secret`, {}),
      deliveries: (id: string, q: { limit?: number } = {}) =>
        call<{ data: WebhookDelivery[] }>("GET", `webhooks/${encodeURIComponent(id)}/deliveries?limit=${q.limit ?? 50}`).then((r) => r.data),
      sendTest: (id: string) => call<{ eventId: string }>("POST", `webhooks/${encodeURIComponent(id)}/test`, {}),
      retry: (deliveryId: string) => call<{ id: string; status: "pending" }>("POST", `webhooks/deliveries/${encodeURIComponent(deliveryId)}/retry`, {}),
    },
    sessions: {
      revoke: (sessionId: string) => call<{ id: string; status: "revoked" }>("POST", `sessions/${encodeURIComponent(sessionId)}/revoke`),
    },
  };
}

const STD = new Set(["sub", "sid", "exp", "iat", "nbf", "iss", "aud", "jti", "azp", "org_id", "org_role", "org_permissions"]);
function customClaims(payload: Record<string, unknown>) {
  return Object.fromEntries(Object.entries(payload).filter(([k]) => !STD.has(k)));
}
