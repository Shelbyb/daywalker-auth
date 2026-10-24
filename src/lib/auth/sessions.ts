import { permissionsOf } from "./org-roles";
import { autoJoinByDomain } from "./org-domains";
import { and, eq, ne } from "drizzle-orm";
import { record } from "../audit";
import { db, schema } from "../db";
import { cache } from "../cache";
import { newId, newToken, sha256 } from "../ids";
import { errors } from "../http";
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

type CachedSession = { id: string; userId: string; status: string; expiresAt: string; createdAt?: string; activeOrgId?: string | null; impersonatorId?: string | null };
const sessKey = (refreshHash: string) => `sess:${refreshHash}`;

export async function createSession(
  inst: Instance,
  userId: string,
  meta: { userAgent?: string | null; ip?: string | null; method?: string; impersonatorId?: string; lifetimeMs?: number },
) {
  // Backstop for every sign-in path: only the identity provider may open a session for an SSO-required address.
  // Platform impersonation (see lib/platform.ts) is not a sign-in by the user, so it is exempt.
  if (meta.method !== "saml" && !meta.impersonatorId) await assertSsoNotRequiredForUser(inst.id, userId);
  // Backstop: an account waiting to be deleted can't sign in (the emailed link cancels it). Impersonation is exempt.
  if (!meta.impersonatorId) {
    const [pend] = await db().select({ at: schema.users.deletionScheduledAt }).from(schema.users).where(eq(schema.users.id, userId));
    if (pend?.at) throw errors.forbidden(`This account is scheduled for deletion on ${pend.at.toISOString().slice(0, 10)}. Use the cancel link in the confirmation email to keep it`).withCode("account_pending_deletion");
  }
  const refreshToken = newToken();
  const ss = sessionSettings(inst);
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
  void record(inst.id, "user.signed_in", { actor: { type: "user", id: userId }, target: userId, data: { sessionId: id, ip: meta.ip ?? null, userAgent: meta.userAgent?.slice(0, 200) ?? null, ...(meta.method ? { method: meta.method } : {}) } });
  return { id, refreshToken, expiresAt };
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
  if (!s?.createdAt) {
    const [row] = await db()
      .select({
        id: schema.sessions.id,
        userId: schema.sessions.userId,
        status: schema.sessions.status,
        expiresAt: schema.sessions.expiresAt,
        createdAt: schema.sessions.createdAt,
        activeOrgId: schema.sessions.activeOrgId,
        impersonatorId: schema.sessions.impersonatorId,
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
      };
      await cache().set(sessKey(h), JSON.stringify(s), "EX", 300);
    }
  }
  if (!s || s.status !== "active" || new Date(s.expiresAt) <= new Date()) return null;
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
  const jwt = await mintSessionToken(inst.id, { sub: s.userId, sid: s.id, azp, org, custom }, inst.settings.tokenTtlSeconds);
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
