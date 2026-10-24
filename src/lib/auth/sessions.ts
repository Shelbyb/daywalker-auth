import { permissionsOf } from "./org-roles";
import { autoJoinByDomain } from "./org-domains";
import { and, eq, isNull, ne } from "drizzle-orm";
import { record } from "../audit";
import { db, schema } from "../db";
import { cache } from "../cache";
import { newId, newToken, sha256 } from "../ids";
import { ApiError, currentRequest, errors } from "../http";
import { requestProof } from "./dpop";
import { getInstance } from "./instance";
import { mintSessionToken } from "./keys";
import { encryptNullable } from "../crypto";
import { roleIn } from "./orgs";
import type { Instance } from "../db/schema";
import { emit } from "../webhooks";
import { assertSsoNotRequiredForUser } from "./sso-policy";
import { HARD_CAP_DAYS, renderClaims, sessionSettings, usesUserVars } from "../session-settings";
import { appRequiresSetup, orgAllowed, setupRequiredError } from "./two-factor-policy";

/** Cookie per instance so multiple apps on one auth origin don't collide. */
export const refreshCookieName = (instanceId: string) => `__dw_rt_${instanceId.slice(4, 14)}`;

type CachedSession = { id: string; userId: string; status: string; expiresAt: string; createdAt?: string; activeOrgId?: string | null; impersonatorId?: string | null; dpopJkt?: string | null; ffAt?: string | null; sfAt?: string | null };
const sessKey = (refreshHash: string) => `sess:${refreshHash}`;

/** How long after sign-in a session may still be bound to a device key (for redirect sign-ins that can't carry a proof). */
export const BIND_WINDOW_MS = 120_000;

export async function createSession(
  inst: Instance,
  userId: string,
  meta: { userAgent?: string | null; ip?: string | null; method?: string; impersonatorId?: string; lifetimeMs?: number; /** Social/SSO/magic-link style sign-in that returns through a browser redirect: no DPoP proof is possible, the SDK binds right after. */ redirectFlow?: boolean; /** The sign-in itself proved a second factor (2FA code, security key, user-verified passkey). */ secondFactor?: boolean },
) {
  // Backstop for every sign-in path: only the identity provider may open a session for an SSO-required address.
  // Platform impersonation (see lib/platform.ts) is not a sign-in by the user, so it is exempt.
  if (meta.method !== "saml" && !meta.impersonatorId) await assertSsoNotRequiredForUser(inst.id, userId);
  // Backstop: an account waiting to be deleted can't sign in (the emailed link cancels it). Impersonation is exempt.
  if (!meta.impersonatorId) {
    const [pend] = await db().select({ at: schema.users.deletionScheduledAt }).from(schema.users).where(eq(schema.users.id, userId));
    if (pend?.at) throw errors.forbidden(`This account is scheduled for deletion on ${pend.at.toISOString().slice(0, 10)}. Use the cancel link in the confirmation email to keep it`).withCode("account_pending_deletion");
  }
  const ss = sessionSettings(inst);
  // Device binding (DPoP): a proof on the request that opens the session ties it to that key.
  let dpopJkt: string | null = null;
  if (!meta.impersonatorId && ss.deviceBinding !== "off") {
    const req = currentRequest.getStore();
    const proof = req ? await requestProof(req, inst.id) : null;
    if (proof) dpopJkt = proof.jkt;
    else if (ss.deviceBinding === "required" && !meta.redirectFlow)
      throw errors.badRequest("device_key_required", "This app requires sessions to be bound to a device key. Send a DPoP proof header (the SDK does this for you)");
  }
  const refreshToken = newToken();
  const expiresAt = new Date(Date.now() + (meta.lifetimeMs ?? (ss.maxLifetimeEnabled ? inst.settings.sessionLifetimeDays : HARD_CAP_DAYS) * 86_400_000));
  const id = newId("sess");
  await db().insert(schema.sessions).values({
    id,
    instanceId: inst.id,
    userId,
    refreshTokenHash: sha256(refreshToken),
    userAgentEnc: encryptNullable(meta.userAgent?.slice(0, 512), `sessions.user_agent:${id}`),
    ipAddressEnc: encryptNullable(meta.ip, `sessions.ip_address:${id}`),
    impersonatorId: meta.impersonatorId ?? null,
    dpopJkt,
    firstFactorAt: new Date(),
    secondFactorAt: meta.secondFactor ? new Date() : null,
    expiresAt,
  });
  // Impersonation is recorded only in the platform audit log: the customer and the user never see it.
  if (meta.impersonatorId) return { id, refreshToken, expiresAt };
  if (!ss.multiSession) {
    const old = await db()
      .update(schema.sessions)
      .set({ status: "revoked" })
      .where(and(eq(schema.sessions.instanceId, inst.id), eq(schema.sessions.userId, userId), eq(schema.sessions.status, "active"), ne(schema.sessions.id, id)))
      .returning({ h: schema.sessions.refreshTokenHash });
    if (old.length) await cache().del(...old.map((r) => sessKey(r.h)));
  }
  await db().update(schema.users).set({ lastSignInAt: new Date() }).where(eq(schema.users.id, userId));
  void autoJoinByDomain(inst, userId); // verified-domain enrollment (never throws, off the request path)
  void emit(inst.id, "session.created", { sessionId: id, userId });
  void record(inst.id, "user.signed_in", { actor: { type: "user", id: userId }, target: userId, data: { sessionId: id, deviceBound: !!dpopJkt, ip: meta.ip ?? null, userAgent: meta.userAgent?.slice(0, 200) ?? null, ...(meta.method ? { method: meta.method } : {}) } });
  return { id, refreshToken, expiresAt };
}

const UNBOUND_OK_PATHS = ["/v1/client/session/bind"];

/**
 * Device binding (DPoP). A bound session needs a proof signed by its key on every request that
 * uses the refresh cookie. When the instance requires binding, a session that is still unbound
 * may only be bound (or looked at) during the short window after sign-in, then it stops working.
 * Impersonation sessions (platform support) are exempt.
 */
async function enforceBinding(instanceId: string, s: CachedSession) {
  if (s.impersonatorId) return;
  const req = currentRequest.getStore();
  if (s.dpopJkt) {
    const proof = req ? await requestProof(req, instanceId) : null;
    if (!proof) throw new ApiError(401, "device_proof_required", "This session is bound to a device key: send a DPoP proof");
    if (proof.jkt !== s.dpopJkt) throw new ApiError(401, "invalid_dpop_proof", "Invalid DPoP proof: not the key this session is bound to");
    return;
  }
  const inst = await getInstance(instanceId);
  if (!inst || sessionSettings(inst).deviceBinding !== "required") return;
  const path = req ? new URL(req.url).pathname : "";
  const allowed = UNBOUND_OK_PATHS.includes(path) || (req?.method === "GET" && path === "/v1/client/session");
  const young = !!s.createdAt && Date.now() - new Date(s.createdAt).getTime() <= BIND_WINDOW_MS;
  if (!(allowed && young)) throw new ApiError(401, "device_binding_required", "This app requires sessions to be bound to a device key: sign in again");
}

/**
 * Binds an unbound session to the device key proven by this request. Only within BIND_WINDOW_MS of
 * sign-in and only once: a session that already has a key can never be re-bound.
 */
export async function bindSession(inst: Instance, refreshToken: string | undefined) {
  if (!refreshToken) throw errors.unauthorized();
  if (sessionSettings(inst).deviceBinding === "off") throw errors.badRequest("device_binding_off", "Device binding is not enabled for this app");
  const req = currentRequest.getStore();
  const proof = req ? await requestProof(req, inst.id) : null;
  if (!proof) throw new ApiError(401, "device_proof_required", "Send a DPoP proof");
  const h = sha256(refreshToken);
  const [row] = await db()
    .select({ id: schema.sessions.id, userId: schema.sessions.userId, status: schema.sessions.status, expiresAt: schema.sessions.expiresAt, createdAt: schema.sessions.createdAt, jkt: schema.sessions.dpopJkt, imp: schema.sessions.impersonatorId })
    .from(schema.sessions)
    .where(and(eq(schema.sessions.refreshTokenHash, h), eq(schema.sessions.instanceId, inst.id)));
  if (!row || row.status !== "active" || row.expiresAt <= new Date() || row.imp) throw errors.unauthorized("Session is no longer active");
  if (row.jkt) throw errors.conflict("already_bound", "This session is already bound to a device key");
  if (Date.now() - row.createdAt.getTime() > BIND_WINDOW_MS) throw errors.forbidden("The window for binding this session has closed: sign in again").withCode("bind_window_closed");
  const done = await db()
    .update(schema.sessions)
    .set({ dpopJkt: proof.jkt })
    .where(and(eq(schema.sessions.id, row.id), isNull(schema.sessions.dpopJkt)))
    .returning({ id: schema.sessions.id });
  if (!done.length) throw errors.conflict("already_bound", "This session is already bound to a device key");
  await cache().del(sessKey(h));
  void record(inst.id, "session.device_bound", { actor: { type: "user", id: row.userId }, target: row.userId, data: { sessionId: row.id } });
  return { sessionId: row.id };
}

/**
 * Hot path: called every ~50s per active tab. Valkey absorbs the read; Postgres is hit
 * on a miss. Revocation deletes the cache entry, so it takes effect on the next refresh.
 */
export async function resolveSession(instanceId: string, refreshToken: string, opts: { inactivityMinutes?: number | null } = {}) {
  const h = sha256(refreshToken);
  let s: CachedSession | null = null;
  const hit = await cache().get(sessKey(h));
  if (hit) s = JSON.parse(hit);
  // Entries cached before createdAt was tracked are re-read once from Postgres.
  if (!s?.createdAt || s.dpopJkt === undefined || s.ffAt === undefined) {
    const [row] = await db()
      .select({
        id: schema.sessions.id,
        userId: schema.sessions.userId,
        status: schema.sessions.status,
        expiresAt: schema.sessions.expiresAt,
        createdAt: schema.sessions.createdAt,
        activeOrgId: schema.sessions.activeOrgId,
        impersonatorId: schema.sessions.impersonatorId,
        dpopJkt: schema.sessions.dpopJkt,
        firstFactorAt: schema.sessions.firstFactorAt,
        secondFactorAt: schema.sessions.secondFactorAt,
        banned: schema.users.banned,
      })
      .from(schema.sessions)
      .innerJoin(schema.users, eq(schema.users.id, schema.sessions.userId))
      .where(and(eq(schema.sessions.refreshTokenHash, h), eq(schema.sessions.instanceId, instanceId)));
    s = null;
    if (row) {
      s = {
        id: row.id,
        userId: row.userId,
        status: row.banned ? "revoked" : row.status,
        expiresAt: row.expiresAt.toISOString(),
        createdAt: row.createdAt.toISOString(),
        activeOrgId: row.activeOrgId,
        impersonatorId: row.impersonatorId,
        dpopJkt: row.dpopJkt,
        ffAt: (row.firstFactorAt ?? row.createdAt).toISOString(),
        sfAt: row.secondFactorAt?.toISOString() ?? null,
      };
      await cache().set(sessKey(h), JSON.stringify(s), "EX", 300);
    }
  }
  if (!s || s.status !== "active" || new Date(s.expiresAt) <= new Date()) return null;
  await enforceBinding(instanceId, s);
  if (opts.inactivityMinutes) {
    const [r] = await db().select({ at: schema.sessions.lastActiveAt }).from(schema.sessions).where(eq(schema.sessions.id, s.id));
    if (r && Date.now() - r.at.getTime() > opts.inactivityMinutes * 60_000) {
      await db().update(schema.sessions).set({ status: "ended" }).where(eq(schema.sessions.id, s.id));
      await cache().del(sessKey(h));
      return null;
    }
  }
  // Throttle last-active writes to once a minute per session.
  if (await cache().set(`sess:touch:${s.id}`, "1", "EX", 60, "NX")) {
    await db().update(schema.sessions).set({ lastActiveAt: new Date() }).where(eq(schema.sessions.id, s.id));
  }
  return s;
}

/** Claims for step-up auth: when each factor was last proved, as ages in seconds at issue time (-1 = never in this session). */
function freshness(s: CachedSession) {
  const now = Date.now();
  const age = (iso: string | null | undefined) => (iso ? Math.max(0, Math.floor((now - new Date(iso).getTime()) / 1000)) : -1);
  const ff = s.ffAt ?? s.createdAt ?? null;
  return { authTime: ff ? Math.floor(new Date(ff).getTime() / 1000) : Math.floor(now / 1000), fva: [age(ff), age(s.sfAt)] as [number, number] };
}

/** Records that this session just proved a factor (step-up). The session cache entry is dropped so the next token shows it. */
export async function markVerified(sessionId: string, instanceId: string, kinds: { first?: boolean; second?: boolean }) {
  const now = new Date();
  const [row] = await db()
    .update(schema.sessions)
    .set({ ...(kinds.first ? { firstFactorAt: now } : {}), ...(kinds.second ? { secondFactorAt: now } : {}) })
    .where(and(eq(schema.sessions.id, sessionId), eq(schema.sessions.instanceId, instanceId), eq(schema.sessions.status, "active")))
    .returning({ h: schema.sessions.refreshTokenHash });
  if (!row) throw errors.unauthorized("Session is no longer active");
  await cache().del(sessKey(row.h));
}

export async function issueToken(inst: Instance, refreshToken: string | undefined, azp?: string) {
  if (!refreshToken) throw errors.unauthorized();
  const ss = sessionSettings(inst);
  const s = await resolveSession(inst.id, refreshToken, { inactivityMinutes: ss.inactivityTimeoutMinutes });
  if (!s) throw errors.unauthorized("Session is no longer active");
  if (!s.impersonatorId && (await appRequiresSetup(inst, s.userId, s.id))) throw setupRequiredError();
  // Role is re-checked on every mint, so removal from an org drops the claims within a minute.
  // An organization that requires two-factor only appears in the token of members who have it.
  const orgRole = s.activeOrgId && (await orgAllowed(s.activeOrgId, s.userId)) ? await roleIn(inst.id, s.activeOrgId, s.userId) : null;
  const org = orgRole ? { org_id: s.activeOrgId!, org_role: orgRole, org_permissions: await permissionsOf(inst.id, orgRole) } : undefined;
  let custom: Record<string, string> | undefined;
  if (Object.keys(ss.customClaims).length) {
    const ctx: Record<string, string | null | undefined> = { "user.id": s.userId, "org.id": org?.org_id, "org.role": org?.org_role };
    if (usesUserVars(ss.customClaims)) {
      const { getUser } = await import("./users");
      const u = await getUser(inst.id, s.userId);
      ctx["user.email"] = u?.emailAddresses.find((e) => e.primary)?.email;
      ctx["user.first_name"] = u?.firstName;
      ctx["user.last_name"] = u?.lastName;
    }
    custom = renderClaims(ss.customClaims, ctx);
  }
  const jwt = await mintSessionToken(inst.id, { sub: s.userId, sid: s.id, azp, org, custom, dpopJkt: s.dpopJkt ?? undefined, fresh: freshness(s) }, inst.settings.tokenTtlSeconds);
  return { jwt, sessionId: s.id, userId: s.userId, orgId: org?.org_id ?? null, orgRole: org?.org_role ?? null };
}

/**
 * For sign-in responses: the token, or `null` with `twoFactorSetupRequired` when the app requires
 * two-factor and this person hasn't set it up (the session cookie is still set, so they can).
 */
export async function issueTokenOrSetup(inst: Instance, refreshToken: string, azp?: string) {
  try {
    return { jwt: (await issueToken(inst, refreshToken, azp)).jwt as string | null, twoFactorSetupRequired: false };
  } catch (e) {
    if (e instanceof Error && (e as { code?: string }).code === "two_factor_setup_required") return { jwt: null, twoFactorSetupRequired: true };
    throw e;
  }
}

export async function endSession(instanceId: string, refreshToken: string, status: "ended" | "revoked" = "ended") {
  const h = sha256(refreshToken);
  const [row] = await db()
    .update(schema.sessions)
    .set({ status })
    .where(and(eq(schema.sessions.refreshTokenHash, h), eq(schema.sessions.instanceId, instanceId)))
    .returning({ id: schema.sessions.id, userId: schema.sessions.userId, impersonatorId: schema.sessions.impersonatorId });
  await cache().del(sessKey(h));
  if (row && status === "ended" && !row.impersonatorId) void record(instanceId, "user.signed_out", { actor: { type: "user", id: row.userId }, target: row.userId, data: { sessionId: row.id } });
}

/** Backend API: revoke by session ID (e.g. "sign out everywhere"). */
export async function revokeSessionById(instanceId: string, sessionId: string) {
  const [row] = await db()
    .update(schema.sessions)
    .set({ status: "revoked" })
    .where(and(eq(schema.sessions.id, sessionId), eq(schema.sessions.instanceId, instanceId)))
    .returning({ h: schema.sessions.refreshTokenHash });
  if (!row) throw errors.notFound("Session not found");
  await cache().del(sessKey(row.h));
  void emit(instanceId, "session.revoked", { sessionId });
}
