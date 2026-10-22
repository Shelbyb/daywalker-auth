/**
 * Data layer for the developer dashboard. Every function takes the signed-in dashboard
 * user's ID and re-checks that they own the instance: the dashboard never trusts an
 * instance ID from the URL or a form.
 */
import { cookies } from "next/headers";
import { and, count, desc, eq, inArray, isNull } from "drizzle-orm";
import { createLocalJWKSet, jwtVerify } from "jose";
import { z } from "zod";
import { db, schema } from "./db";
import { cache, rateLimit } from "./cache";
import { env } from "./env";
import { errors } from "./http";
import { listAudit, record, type AuditQuery } from "./audit";
import { newId, newToken, sha256 } from "./ids";
import { invalidateInstance, parsePublishableKey, publishableKey } from "./auth/instance";
import { createSigningKey, getJwks, issuerFor, listSigningKeys, rotateSigningKey } from "./auth/keys";
import { getUser, deleteUser, setBanned } from "./auth/users";
import { PROVIDERS, callbackUrl, setProviderConfig, type ProviderName } from "./auth/oauth";
import { legalInput, legalOf } from "./auth/legal";
import type { Instance } from "./db/schema";

const MAX_INSTANCES = 5;
const MAX_KEYS = 10;
const SESSION_COOKIE = "__dw_session"; // same cookie the SDK keeps fresh

const platformKey = () => process.env.PLATFORM_PUBLISHABLE_KEY || undefined;
export const platformInstanceId = () => parsePublishableKey(platformKey());
export const dashboardEnabled = () => !!platformInstanceId();

/** Config for the SDK's authProxy: the dashboard signs developers in through the platform instance. */
export function platformConfig() {
  const pk = platformKey();
  if (!pk) throw new Error("PLATFORM_PUBLISHABLE_KEY is not set");
  return { publishableKey: pk, frontendApi: env().APP_URL };
}

// ---------- Who is signed in ----------

/** Verifies the session cookie locally (no network hop). Null when signed out. */
export async function getDashboardUser() {
  const instanceId = platformInstanceId();
  if (!instanceId) return null;
  const token = (await cookies()).get(SESSION_COOKIE)?.value;
  if (!token) return null;
  try {
    const { payload } = await jwtVerify(token, createLocalJWKSet(await getJwks(instanceId)), {
      issuer: issuerFor(instanceId),
      algorithms: ["ES256"],
      clockTolerance: 5,
      requiredClaims: ["sub", "sid", "exp", "iat"],
    });
    if (typeof payload.azp === "string" && payload.azp !== new URL(env().APP_URL).origin) return null;
    return { userId: payload.sub!, sessionId: payload.sid as string };
  } catch {
    return null;
  }
}

/** For pages and actions: the signed-in user, or a 401. */
export async function requireDashboardUser() {
  const u = await getDashboardUser();
  if (!u) throw errors.unauthorized();
  return u;
}

export async function dashboardProfile(userId: string) {
  const instanceId = platformInstanceId();
  const u = instanceId ? await getUser(instanceId, userId) : null;
  return {
    email: u?.emailAddresses.find((e) => e.primary)?.email ?? null,
    name: [u?.firstName, u?.lastName].filter(Boolean).join(" ") || null,
  };
}

/** Every developer gets their own account on first visit. */
export async function ensureAccount(userId: string) {
  const [existing] = await db().select({ id: schema.accountMembers.accountId }).from(schema.accountMembers).where(eq(schema.accountMembers.userId, userId)).limit(1);
  if (existing) return existing.id;
  const id = newId("acct");
  await db().transaction(async (tx) => {
    await tx.insert(schema.accounts).values({ id, name: "Personal" });
    await tx.insert(schema.accountMembers).values({ accountId: id, userId });
  });
  return id;
}

async function accountIds(userId: string) {
  return (await db().select({ id: schema.accountMembers.accountId }).from(schema.accountMembers).where(eq(schema.accountMembers.userId, userId))).map((r) => r.id);
}

/** The instance, only if this user's account owns it. Anything else is a 404 (existence isn't revealed). */
export async function ownedInstance(userId: string, instanceId: string): Promise<Instance> {
  const ids = await accountIds(userId);
  const [row] = ids.length
    ? await db().select().from(schema.instances).where(and(eq(schema.instances.id, instanceId), inArray(schema.instances.accountId, ids)))
    : [];
  if (!row || row.id === platformInstanceId()) throw errors.notFound("Instance not found");
  return row;
}

// ---------- Instances ----------

export async function listInstances(userId: string) {
  const ids = await accountIds(userId);
  if (!ids.length) return [];
  const rows = await db().select().from(schema.instances).where(inArray(schema.instances.accountId, ids)).orderBy(desc(schema.instances.createdAt));
  return rows.map((i) => ({ id: i.id, name: i.name, environment: i.environment, publishableKey: publishableKey(i), createdAt: i.createdAt }));
}

const sanitizeName = z.string().trim().min(1, "Give it a name").max(60);

/** Creates an instance with its signing key and first secret key (returned once). */
export async function createInstance(userId: string, input: { name: string; environment: "development" | "production" }) {
  const name = sanitizeName.parse(input.name);
  if (!["development", "production"].includes(input.environment)) throw errors.badRequest("invalid_environment", "Pick development or production");
  if ((await rateLimit(`dash:create_instance:${userId}`, 10, 3600)) < 0) throw errors.tooMany();
  const accountId = await ensureAccount(userId);
  const [{ n }] = await db().select({ n: count() }).from(schema.instances).where(eq(schema.instances.accountId, accountId));
  if (n >= MAX_INSTANCES) throw errors.badRequest("too_many_instances", `You can have up to ${MAX_INSTANCES} instances`);
  const id = newId("ins");
  const [inst] = await db().insert(schema.instances).values({ id, accountId, name, environment: input.environment }).returning();
  await createSigningKey(id);
  const secretKey = await insertKey(inst, "Default");
  return { id, publishableKey: publishableKey(inst), secretKey };
}

export async function deleteInstance(userId: string, instanceId: string, confirmName: string) {
  const inst = await ownedInstance(userId, instanceId);
  if (confirmName.trim() !== inst.name) throw errors.badRequest("name_mismatch", "Type the instance name exactly to confirm");
  const keys = await db().select({ h: schema.apiKeys.keyHash }).from(schema.apiKeys).where(eq(schema.apiKeys.instanceId, instanceId));
  const sess = await db().select({ h: schema.sessions.refreshTokenHash }).from(schema.sessions).where(eq(schema.sessions.instanceId, instanceId));
  await db().delete(schema.instances).where(eq(schema.instances.id, instanceId)); // cascades to everything inside it
  const stale = [...keys.map((k) => `sk:${k.h}`), ...sess.map((s) => `sess:${s.h}`), `jwks:${instanceId}`];
  if (stale.length) await cache().del(...stale);
  await invalidateInstance(instanceId);
}

// ---------- Settings ----------

function origins(list: string[]) {
  const out = new Set<string>();
  for (const raw of list.map((s) => s.trim()).filter(Boolean)) {
    let u: URL;
    try {
      u = new URL(raw);
    } catch {
      throw errors.badRequest("invalid_origin", `"${raw}" isn't a valid URL`);
    }
    const local = u.protocol === "http:" && (u.hostname === "localhost" || u.hostname === "127.0.0.1");
    if (u.protocol !== "https:" && !local) throw errors.badRequest("invalid_origin", `"${raw}" must use https (http is only allowed for localhost)`);
    out.add(u.origin);
  }
  if (out.size > 20) throw errors.badRequest("too_many_origins", "Up to 20 origins");
  return [...out];
}

export async function updateSettings(
  userId: string,
  instanceId: string,
  input: { name: string; allowedOrigins: string[]; passwordMinLength: number; sessionLifetimeDays: number; emailCodeSignIn?: boolean },
) {
  const inst = await ownedInstance(userId, instanceId);
  const s = z
    .object({
      name: sanitizeName,
      passwordMinLength: z.coerce.number().int().min(8).max(128),
      sessionLifetimeDays: z.coerce.number().int().min(1).max(90),
    })
    .parse(input);
  await db()
    .update(schema.instances)
    .set({
      name: s.name,
      allowedOrigins: origins(input.allowedOrigins),
      settings: { ...inst.settings, passwordMinLength: s.passwordMinLength, sessionLifetimeDays: s.sessionLifetimeDays, emailCodeSignIn: input.emailCodeSignIn === true },
      updatedAt: new Date(),
    })
    .where(eq(schema.instances.id, instanceId));
  await invalidateInstance(instanceId);
  void record(instanceId, "instance.settings_updated", { actor: { type: "developer", id: userId }, data: { name: s.name, passwordMinLength: s.passwordMinLength, sessionLifetimeDays: s.sessionLifetimeDays, emailCodeSignIn: input.emailCodeSignIn === true } });
}

export async function updateLegal(userId: string, instanceId: string, input: unknown) {
  await ownedInstance(userId, instanceId);
  const legal = legalInput.parse(input);
  await db().update(schema.instances).set({ legal, updatedAt: new Date() }).where(eq(schema.instances.id, instanceId));
  await invalidateInstance(instanceId);
  void record(instanceId, "instance.terms_updated", { actor: { type: "developer", id: userId } });
}

export async function instanceDetails(userId: string, instanceId: string) {
  const inst = await ownedInstance(userId, instanceId);
  const [{ users }] = await db().select({ users: count() }).from(schema.users).where(eq(schema.users.instanceId, instanceId));
  return {
    id: inst.id,
    name: inst.name,
    environment: inst.environment,
    publishableKey: publishableKey(inst),
    frontendApi: env().APP_URL,
    allowedOrigins: inst.allowedOrigins,
    settings: inst.settings,
    legal: legalOf(inst),
    userCount: users,
    createdAt: inst.createdAt,
  };
}

// ---------- Signing keys ----------

export async function signingKeysFor(userId: string, instanceId: string) {
  await ownedInstance(userId, instanceId);
  return listSigningKeys(instanceId);
}

export async function rotateKeys(userId: string, instanceId: string) {
  await ownedInstance(userId, instanceId);
  if ((await rateLimit(`${instanceId}:rotate_key`, 5, 3600)) < 0) throw errors.tooMany();
  const r = await rotateSigningKey(instanceId);
  void record(instanceId, "signing_key.rotated", { actor: { type: "developer", id: userId } });
  return r;
}

// ---------- Secret keys ----------

async function insertKey(inst: Instance, name: string) {
  const secret = `sk_${inst.environment === "production" ? "live" : "test"}_${newToken(32)}`;
  await db().insert(schema.apiKeys).values({ id: newId("sk"), instanceId: inst.id, name, keyHash: sha256(secret), keyPrefix: secret.slice(0, 12) });
  return secret;
}

export async function listKeys(userId: string, instanceId: string) {
  await ownedInstance(userId, instanceId);
  const rows = await db().select().from(schema.apiKeys).where(and(eq(schema.apiKeys.instanceId, instanceId), isNull(schema.apiKeys.revokedAt))).orderBy(desc(schema.apiKeys.createdAt));
  return rows.map((k) => ({ id: k.id, name: k.name, prefix: k.keyPrefix, lastUsedAt: k.lastUsedAt, createdAt: k.createdAt }));
}

/** The full key is returned once and never stored (only its hash is). */
export async function createKey(userId: string, instanceId: string, name: string) {
  const inst = await ownedInstance(userId, instanceId);
  const label = sanitizeName.parse(name);
  const [{ n }] = await db().select({ n: count() }).from(schema.apiKeys).where(and(eq(schema.apiKeys.instanceId, instanceId), isNull(schema.apiKeys.revokedAt)));
  if (n >= MAX_KEYS) throw errors.badRequest("too_many_keys", `Up to ${MAX_KEYS} active keys. Revoke one first`);
  const secret = await insertKey(inst, label);
  void record(instanceId, "api_key.created", { actor: { type: "developer", id: userId }, data: { name: label, prefix: secret.slice(0, 12) } });
  return secret;
}

export async function revokeKey(userId: string, instanceId: string, keyId: string) {
  await ownedInstance(userId, instanceId);
  const [row] = await db()
    .update(schema.apiKeys)
    .set({ revokedAt: new Date() })
    .where(and(eq(schema.apiKeys.id, keyId), eq(schema.apiKeys.instanceId, instanceId), isNull(schema.apiKeys.revokedAt)))
    .returning({ h: schema.apiKeys.keyHash });
  if (!row) throw errors.notFound("Key not found");
  await cache().del(`sk:${row.h}`); // takes effect immediately, not after the 60s cache
  void record(instanceId, "api_key.revoked", { actor: { type: "developer", id: userId }, target: keyId });
}

// ---------- Social providers ----------

export async function listProviders(userId: string, instanceId: string) {
  await ownedInstance(userId, instanceId);
  const rows = await db().select().from(schema.oauthProviders).where(eq(schema.oauthProviders.instanceId, instanceId));
  return PROVIDERS.map((p) => {
    const r = rows.find((x) => x.provider === p);
    return { provider: p, configured: !!r, enabled: !!r?.enabled, clientId: r?.clientId ?? null, redirectUri: callbackUrl(p) };
  });
}

/** The client secret is encrypted and never shown again, so saving always needs it re-entered. */
export async function saveProvider(userId: string, instanceId: string, provider: string, input: { clientId: string; clientSecret: string; enabled: boolean }) {
  await ownedInstance(userId, instanceId);
  if (!(PROVIDERS as string[]).includes(provider)) throw errors.notFound("Unknown provider");
  const cfg = z
    .object({ clientId: z.string().trim().min(1).max(256), clientSecret: z.string().min(1).max(512), enabled: z.boolean() })
    .parse(input);
  await setProviderConfig(instanceId, provider as ProviderName, cfg);
  void record(instanceId, "social_provider.saved", { actor: { type: "developer", id: userId }, target: provider, data: { enabled: cfg.enabled } });
}

export async function setProviderEnabled(userId: string, instanceId: string, provider: string, enabled: boolean) {
  await ownedInstance(userId, instanceId);
  if (!(PROVIDERS as string[]).includes(provider)) throw errors.notFound("Unknown provider");
  await db()
    .update(schema.oauthProviders)
    .set({ enabled, updatedAt: new Date() })
    .where(and(eq(schema.oauthProviders.instanceId, instanceId), eq(schema.oauthProviders.provider, provider as ProviderName)));
  await cache().del(`oauth:enabled:${instanceId}`);
  void record(instanceId, enabled ? "social_provider.enabled" : "social_provider.disabled", { actor: { type: "developer", id: userId }, target: provider });
}

// ---------- Users ----------

export async function listUsers(userId: string, instanceId: string, q: { limit?: number; offset?: number } = {}) {
  await ownedInstance(userId, instanceId);
  const limit = Math.min(Math.max(q.limit ?? 20, 1), 100);
  const rows = await db()
    .select({ id: schema.users.id })
    .from(schema.users)
    .where(eq(schema.users.instanceId, instanceId))
    .orderBy(desc(schema.users.createdAt))
    .limit(limit)
    .offset(Math.max(q.offset ?? 0, 0));
  const users = await Promise.all(rows.map((r) => getUser(instanceId, r.id, { includePrivate: true })));
  return users.filter((u) => !!u).map((u) => ({
    id: u!.id,
    email: u!.emailAddresses.find((e) => e.primary)?.email ?? null,
    verified: !!u!.emailAddresses.find((e) => e.primary)?.verified,
    name: [u!.firstName, u!.lastName].filter(Boolean).join(" ") || null,
    twoFactorEnabled: u!.twoFactorEnabled,
    banned: !!(u as { banned?: boolean }).banned,
    lastSignInAt: u!.lastSignInAt,
    createdAt: u!.createdAt,
  }));
}

export async function banUser(userId: string, instanceId: string, targetId: string, banned: boolean) {
  await ownedInstance(userId, instanceId);
  await setBanned(instanceId, targetId, banned);
  void record(instanceId, banned ? "user.banned" : "user.unbanned", { actor: { type: "developer", id: userId }, target: targetId });
}

export async function removeUser(userId: string, instanceId: string, targetId: string) {
  await ownedInstance(userId, instanceId);
  await deleteUser(instanceId, targetId);
  void record(instanceId, "user.deleted", { actor: { type: "developer", id: userId }, target: targetId });
}

// ---------- Audit log ----------

export async function auditFor(userId: string, instanceId: string, q: AuditQuery) {
  await ownedInstance(userId, instanceId);
  return listAudit(instanceId, q);
}
