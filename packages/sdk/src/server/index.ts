import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { createRemoteJWKSet, jwtVerify, errors as joseErrors } from "jose";
import { instanceIdFromKey, issuerFor, type Config } from "../core/keys";
import { isRecentlyVerified, type RecentAuthCheck, type ReverificationLevel } from "../core/fresh";

if (typeof window !== "undefined") {
  // Secret keys must never reach a browser bundle.
  throw new Error("@daywalker/auth/server must only be imported on the server");
}

export type SessionClaims = { userId: string; sessionId: string; issuedAt: number; expiresAt: number; azp?: string; orgId?: string; orgRole?: string; /** Permissions of `orgRole` in the active organization, e.g. "org:billing:manage". */ orgPermissions?: string[]; /** Custom claims set in the dashboard. */ claims?: Record<string, unknown>; /** Thumbprint of the device key this session is bound to (DPoP `cnf.jkt`); undefined when unbound. */ deviceKey?: string; /** When the first factor was last proved (seconds since epoch; the claim `auth_time`). */ authTime?: number; /** Age in seconds of the first and second factor when the token was issued, -1 = never in this session (claim `fva`). Use `requireRecentAuth` instead of reading it. */ fva?: [number, number] };

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
    return { userId: payload.sub!, sessionId: payload.sid as string, issuedAt: payload.iat!, expiresAt: payload.exp!, azp, orgId, orgRole, orgPermissions, claims: customClaims(payload), authTime: typeof payload.auth_time === "number" ? payload.auth_time : undefined, fva: Array.isArray(payload.fva) && payload.fva.length === 2 && payload.fva.every((n) => typeof n === "number") ? (payload.fva as [number, number]) : undefined, deviceKey: (payload.cnf as { jkt?: unknown } | undefined)?.jkt && typeof (payload.cnf as { jkt: unknown }).jkt === "string" ? (payload.cnf as { jkt: string }).jkt : undefined };
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

export { isRecentlyVerified, type ReverificationLevel, type RecentAuthCheck };

/** 403 `reverification_required`: the React SDK's `authFetch` sees this, asks the person to prove themselves, and retries. */
export class ReverificationRequiredError extends ForbiddenError {
  code = "reverification_required";
  constructor(public reverification: Required<RecentAuthCheck>) {
    super("Reverification required");
    this.name = "ReverificationRequiredError";
  }
  /** The response to send: `return error.toResponse()` in a route handler. */
  toResponse() {
    return reverificationResponse(this.reverification);
  }
}

/** The JSON 403 that tells the browser SDK to run its reverification prompt and retry the request. */
export function reverificationResponse(check: RecentAuthCheck) {
  const reverification = { level: check.level ?? "first_factor", maxAge: check.maxAge };
  return Response.json({ error: { code: "reverification_required", message: "Reverification required", reverification } }, { status: 403, headers: { "cache-control": "no-store" } });
}

/** Throws `ReverificationRequiredError` unless `isRecentlyVerified`. Call it at the top of a sensitive route or server action. */
export function requireRecentAuth(claims: Pick<SessionClaims, "fva" | "issuedAt"> | null | undefined, check: RecentAuthCheck): void {
  if (!isRecentlyVerified(claims, check)) throw new ReverificationRequiredError({ level: check.level ?? "first_factor", maxAge: check.maxAge });
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

export type AuditChainStatus = {
  /** Every chained entry checks out. */
  ok: boolean;
  /** False until the instance has recorded its first chained entry. */
  chained: boolean;
  checked: number;
  firstSeq: number | null;
  lastSeq: number | null;
  /** Where the chain ends now. Keep `hash` somewhere safe (a secret manager, a ticket): it detects a later rewrite or truncation. */
  head: { seq: number; hash: string } | null;
  startedAt: string | null;
  purged: { seq: number; hash: string } | null;
  problem?: { seq: number; id: string | null; reason: string; message: string };
};
export type AuditExportConfigStatus =
  | { configured: false }
  | { configured: true; endpoint: string | null; region: string; bucket: string; prefix: string; pathStyle: boolean; serverSideEncryption: boolean; enabled: boolean; accessKeyId: string; lastPushedSeq: number; lastPushedAt: string | null; lastError: string | null; lastErrorAt: string | null };
export type AuditExportConfigInput = { endpoint?: string | null; region: string; bucket: string; prefix?: string; pathStyle?: boolean; serverSideEncryption?: boolean; enabled?: boolean; accessKeyId?: string; secretAccessKey?: string };

export type AuditExportCheck = {
  ok: boolean;
  /** Chained entries in the file. */
  entries: number;
  /** Entries from before the hash chain existed (not covered). */
  unchained: number;
  firstSeq: number | null;
  lastSeq: number | null;
  /** The `prevHash` of the first chained entry: for a file that starts mid-chain, this is the previous file's `headHash`. */
  firstPrevHash: string | null;
  /** The hash of the last chained entry: pin it, and pass it as `after` when checking the next file. */
  headHash: string | null;
  problem?: { line: number; seq: number | null; reason: "malformed" | "missing_header" | "missing_footer" | "count_mismatch" | "wrong_instance" | "hash_mismatch" | "prev_hash_mismatch" | "sequence_gap" | "wrong_start" | "wrong_head"; message: string };
};

/**
 * Checks an audit export (NDJSON from the dashboard, `auditEvents.exportText()` or a bucket file) offline, with no
 * key: every entry's hash is recomputed from its fields, each entry must point at the one before, sequence numbers
 * must be consecutive, and the footer must account for every line. Pass `after` (the previous file's `headHash` and
 * last `seq`) to prove a file continues the one before it, and `expectedHead` to prove the log ends where you
 * recorded it. It cannot read the details against their `dataDigest` (that needs the service's key); the
 * dashboard's "Verify integrity" and `auditEvents.verify()` do that.
 */
export function verifyAuditExport(ndjson: string, opts: { after?: { seq: number; hash: string }; expectedHead?: string } = {}): AuditExportCheck {
  const lines = ndjson.split("\n").filter((l) => l.trim() !== "");
  const out: AuditExportCheck = { ok: false, entries: 0, unchained: 0, firstSeq: null, lastSeq: null, firstPrevHash: null, headHash: null };
  const bad = (line: number, seq: number | null, reason: NonNullable<AuditExportCheck["problem"]>["reason"], message: string): AuditExportCheck => ({ ...out, problem: { line, seq, reason, message } });
  let header = null as { instanceId?: string; chain?: { purgedSeq?: number; purgedHash?: string } | null } | null;
  let footer = null as { count?: number } | null;
  let events = 0;
  let prev: { seq: number; hash: string } | null = opts.after ?? null;
  for (let i = 0; i < lines.length; i++) {
    let j: Record<string, unknown>;
    try {
      j = JSON.parse(lines[i]);
    } catch {
      return bad(i + 1, null, "malformed", "A line isn't valid JSON");
    }
    if (j.type === "daywalker.audit.header") { header = j as typeof header; continue; }
    if (j.type === "daywalker.audit.footer") { footer = j as typeof footer; continue; }
    if (j.type !== "event") return bad(i + 1, null, "malformed", "Unknown line type");
    if (!header?.instanceId) return bad(i + 1, null, "missing_header", "The file doesn't start with a header");
    events++;
    if (j.seq === null || j.seq === undefined) { out.unchained++; continue; }
    const seq = j.seq as number;
    const actor = (j.actor ?? {}) as { type?: string; id?: string | null };
    const hash = createHash("sha256")
      .update(JSON.stringify(["dw-audit-v1", header.instanceId, seq, j.prevHash, j.id, j.event, actor.type, actor.id ?? null, j.target ?? null, j.createdAt, j.dataDigest ?? ""]))
      .digest("hex");
    if (hash !== j.hash) return bad(i + 1, seq, "hash_mismatch", "An entry's contents don't match its hash");
    if (prev) {
      if (seq !== prev.seq + 1) return bad(i + 1, seq, "sequence_gap", "An entry is missing from the sequence");
      if (j.prevHash !== prev.hash) return bad(i + 1, seq, "prev_hash_mismatch", "An entry doesn't follow from the one before it");
    } else if (header.chain && header.chain.purgedSeq === 0 && seq === 1 && j.prevHash !== "0".repeat(64)) {
      return bad(i + 1, seq, "wrong_start", "The first entry doesn't start from the empty chain");
    } else if (header.chain && header.chain.purgedSeq !== undefined && header.chain.purgedSeq > 0 && seq === header.chain.purgedSeq + 1 && j.prevHash !== header.chain.purgedHash) {
      return bad(i + 1, seq, "wrong_start", "The first entry doesn't follow from the entries retention removed");
    }
    if (out.firstSeq === null) { out.firstSeq = seq; out.firstPrevHash = j.prevHash as string; }
    out.lastSeq = seq;
    out.entries++;
    prev = { seq, hash };
    out.headHash = hash;
  }
  if (!header) return bad(0, null, "missing_header", "The file doesn't start with a header");
  if (!footer) return bad(lines.length, null, "missing_footer", "The file has no footer: it may have been cut short");
  if (footer.count !== events) return bad(lines.length, null, "count_mismatch", "The footer's entry count doesn't match the file");
  if (opts.expectedHead && out.headHash !== opts.expectedHead) return bad(lines.length, out.lastSeq, "wrong_head", "The log doesn't end at the hash you recorded");
  return { ...out, ok: true };
}

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
      /** Stops a pending self-service deletion. `canceled` is false if none was pending. */
      cancelDeletion: (userId: string) => call<{ id: string; canceled: boolean }>("POST", `users/${encodeURIComponent(userId)}/cancel_deletion`, {}),
    },
    /** Whether users can delete their own account, and the grace period (0 to 90 days). */
    accountDeletion: {
      get: () => call<{ enabled: boolean; graceDays: number }>("GET", "instance/account_deletion"),
      update: (v: { enabled?: boolean; graceDays?: number }) => call<{ enabled: boolean; graceDays: number }>("PATCH", "instance/account_deletion", v),
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
      /** Recomputes the tamper-evident hash chain of the audit log. See `AuditChainStatus`. */
      verify: () => call<AuditChainStatus>("GET", "audit_events/verify"),
      /** The log as NDJSON text (details decrypted, with `prevHash` / `hash` per entry). Check it with `verifyAuditExport`. */
      exportText: async (q: { from?: string; to?: string } = {}) => {
        const p = new URLSearchParams();
        for (const [k, v] of Object.entries(q)) if (v) p.set(k, v);
        const res = await fetch(`${base}/v1/audit_events/export${p.size ? `?${p}` : ""}`, { headers: { authorization: `Bearer ${opts.secretKey}` }, cache: "no-store" });
        if (!res.ok) {
          const body = await res.json().catch(() => ({}));
          throw new BackendError(res.status, body.error?.code ?? "unknown", body.error?.message ?? "Request failed");
        }
        return res.text();
      },
    },
    /** Push of the audit log to your own S3-compatible bucket. The secret access key is write-only. */
    auditExport: {
      get: () => call<AuditExportConfigStatus>("GET", "instance/audit_export"),
      /** Omit both keys on an update to keep the current ones. */
      set: (c: AuditExportConfigInput) => call<AuditExportConfigStatus>("PUT", "instance/audit_export", c),
      remove: () => call<{ removed: boolean }>("DELETE", "instance/audit_export"),
      /** Writes a small test object to the bucket. */
      test: () => call<{ ok: true; key: string }>("POST", "instance/audit_export/test", {}),
      /** Pushes entries not yet in the bucket (the server also does this every 15 minutes). */
      push: () => call<{ pushed: number; objects: number; lastSeq: number }>("POST", "instance/audit_export/push", {}),
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

const STD = new Set(["sub", "sid", "exp", "iat", "nbf", "iss", "aud", "jti", "azp", "org_id", "org_role", "org_permissions", "cnf", "auth_time", "fva"]);
function customClaims(payload: Record<string, unknown>) {
  return Object.fromEntries(Object.entries(payload).filter(([k]) => !STD.has(k)));
}
