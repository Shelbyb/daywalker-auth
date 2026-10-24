/**
 * Data layer for the developer dashboard. Every function takes the signed-in dashboard
 * user's ID and re-checks that they own the instance: the dashboard never trusts an
 * instance ID from the URL or a form.
 */
import { cancelDeletion } from "./auth/account-deletion";
import { requireFeature } from "./plans";
import { protectionView, updateProtection } from "./auth/instance-policy";
import { createScimToken, revokeScimToken } from "./auth/scim";
import { cookies } from "next/headers";
import { and, count, desc, eq, inArray, isNull } from "drizzle-orm";
import { createLocalJWKSet, jwtVerify } from "jose";
import { z } from "zod";
import { db, schema } from "./db";
import { cache, rateLimit } from "./cache";
import { env } from "./env";
import { errors } from "./http";
import { listAudit, record, type AuditQuery } from "./audit";
import { SAMPLE_VARS, accentInput, composeEmail, isTemplateKind, listTemplates, resetTemplate, saveTemplate } from "./email-templates";
import { sendMail } from "./mail";
import { smsConfigured, parseCallingCodes } from "./sms";
import { createConnection, deleteConnection, listConnections, updateConnection } from "./auth/saml";
import { newId, newToken, sha256 } from "./ids";
import { invalidateInstance, parsePublishableKey, publishableKey } from "./auth/instance";
import { createSigningKey, getJwks, issuerFor, listSigningKeys, rotateSigningKey } from "./auth/keys";
import { getUser, deleteUser, setBanned } from "./auth/users";
import { unlockUser } from "./auth/lockout";
import { roleKey, listRoles, createRole, updateRole, deleteRole, roleInput, roleUpdate } from "./auth/org-roles";
import { PROVIDERS, callbackUrl, isProvider, labelFor, setProviderConfig } from "./auth/oauth";
import { parseSettings, type ProviderSettings } from "./auth/oauth-providers";
import { legalInput, legalOf } from "./auth/legal";
import { validateClaims } from "./session-settings";
import type { Instance } from "./db/schema";
import { platformRole } from "./platform-staff";
import { recordPlatform } from "./platform-audit";

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

/**
 * The instance, only if this user's account owns it, or the user is platform staff (who can manage
 * every customer instance; that access is logged in the platform audit log, at most hourly per
 * instance). Anything else is a 404 (existence isn't revealed).
 */
export async function ownedInstance(userId: string, instanceId: string): Promise<Instance> {
  const ids = await accountIds(userId);
  let [row] = ids.length
    ? await db().select().from(schema.instances).where(and(eq(schema.instances.id, instanceId), inArray(schema.instances.accountId, ids)))
    : [];
  if (!row && typeof instanceId === "string" && instanceId.length <= 100) {
    const role = await platformRole(userId);
    const isPlatform = instanceId === platformInstanceId();
    // Staff manage customer instances; only admins manage the platform's own instance (its sign-in settings).
    if (role && (!isPlatform || role === "admin")) [row] = await db().select().from(schema.instances).where(eq(schema.instances.id, instanceId));
    if (row && row.id !== platformInstanceId() && (await cache().set(`platform:accessed:${userId}:${row.id}`, "1", "EX", 3600, "NX")))
      void recordPlatform("instance.accessed", { actorId: userId, instanceId: row.id, data: { instanceName: row.name } });
  }
  if (!row) throw errors.notFound("Instance not found");
  return row;
}

/** True when the instance is reachable only because the viewer is platform staff (not their own). */
export async function viewingAsStaff(userId: string, instanceId: string) {
  const ids = await accountIds(userId);
  if (!ids.length) return true;
  const [row] = await db().select({ id: schema.instances.id }).from(schema.instances).where(and(eq(schema.instances.id, instanceId), inArray(schema.instances.accountId, ids)));
  return !row;
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

function smsCountries(raw: string | undefined) {
  try {
    return parseCallingCodes([raw ?? ""]);
  } catch (e) {
    throw errors.badRequest("invalid_countries", (e as Error).message);
  }
}

export async function updateSettings(
  userId: string,
  instanceId: string,
  input: { name: string; allowedOrigins: string[]; passwordMinLength: number; sessionLifetimeDays: number; emailCodeSignIn?: boolean; breachedPasswordCheck?: boolean; smsSecondFactor?: boolean; smsCountries?: string },
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
      settings: { ...inst.settings, passwordMinLength: s.passwordMinLength, sessionLifetimeDays: s.sessionLifetimeDays, emailCodeSignIn: input.emailCodeSignIn === true, breachedPasswordCheck: input.breachedPasswordCheck !== false, smsSecondFactor: input.smsSecondFactor === true, smsCountries: smsCountries(input.smsCountries) },
      updatedAt: new Date(),
    })
    .where(eq(schema.instances.id, instanceId));
  await invalidateInstance(instanceId);
  void record(instanceId, "instance.settings_updated", { actor: { type: "developer", id: userId }, data: { name: s.name, passwordMinLength: s.passwordMinLength, sessionLifetimeDays: s.sessionLifetimeDays, emailCodeSignIn: input.emailCodeSignIn === true, breachedPasswordCheck: input.breachedPasswordCheck !== false, smsSecondFactor: input.smsSecondFactor === true } });
}

export async function updateLegal(userId: string, instanceId: string, input: unknown) {
  await ownedInstance(userId, instanceId);
  const legal = legalInput.parse(input);
  await db().update(schema.instances).set({ legal, updatedAt: new Date() }).where(eq(schema.instances.id, instanceId));
  await invalidateInstance(instanceId);
  void record(instanceId, "instance.terms_updated", { actor: { type: "developer", id: userId } });
}

const orgLimit = z.union([z.literal("").transform(() => null), z.coerce.number().int().min(1).max(10000)]);

/** Organization rules for the frontend API (see lib/org-settings.ts). Limits: whole numbers 1..10000, blank = unlimited. */
export async function updateOrgSettings(
  userId: string,
  instanceId: string,
  input: { enabled: boolean; membershipLimit: string; allowUserCreation: boolean; creationLimit: string; creatorRole: string; defaultRole: string; allowAdminDelete: boolean; allowPersonalAccounts: boolean },
) {
  const inst = await ownedInstance(userId, instanceId);
  await requireFeature(inst.accountId, "organization_settings");
  const parsed = z
    .object({
      enabled: z.boolean(),
      membershipLimit: orgLimit,
      allowUserCreation: z.boolean(),
      creationLimit: orgLimit,
      creatorRole: roleKey,
      defaultRole: roleKey,
      allowAdminDelete: z.boolean(),
      allowPersonalAccounts: z.boolean(),
    })
    .safeParse({ ...input, membershipLimit: input.membershipLimit.trim(), creationLimit: input.creationLimit.trim() });
  if (!parsed.success) {
    const field = String(parsed.error.issues[0]?.path[0] ?? "");
    if (field === "membershipLimit" || field === "creationLimit")
      throw errors.badRequest("invalid_limit", `${field === "membershipLimit" ? "Membership limit" : "Creation limit"} must be a whole number from 1 to 10000, or blank for unlimited`);
    throw errors.badRequest("invalid_role", "Choose an existing role");
  }
  const known = await listRoles(instanceId);
  if (!known.some((r) => r.key === parsed.data.creatorRole) || !known.some((r) => r.key === parsed.data.defaultRole)) throw errors.badRequest("invalid_role", "Choose an existing role");
  const organizations = parsed.data;
  await db().update(schema.instances).set({ settings: { ...inst.settings, organizations }, updatedAt: new Date() }).where(eq(schema.instances.id, instanceId));
  await invalidateInstance(instanceId);
  void record(instanceId, "instance.organizations_updated", { actor: { type: "developer", id: userId }, data: organizations });
}

/** Session rules (see lib/session-settings.ts). Claims are a JSON object of name -> template. */
export async function updateSessionSettings(
  userId: string,
  instanceId: string,
  input: { maxLifetimeEnabled: boolean; inactivityTimeoutMinutes: string; multiSession: boolean; tokenTtlSeconds: string; customClaims: string },
) {
  const inst = await ownedInstance(userId, instanceId);
  if (input.inactivityTimeoutMinutes.trim() !== "" || (input.customClaims.trim() && input.customClaims.trim() !== "{}")) await requireFeature(inst.accountId, "session_customization");
  const idle = input.inactivityTimeoutMinutes.trim();
  const inactivityTimeoutMinutes = idle === "" ? null : Number(idle);
  if (inactivityTimeoutMinutes !== null && (!Number.isInteger(inactivityTimeoutMinutes) || inactivityTimeoutMinutes < 1 || inactivityTimeoutMinutes > 129600))
    throw errors.badRequest("invalid_timeout", "Inactivity timeout must be a whole number of minutes from 1 to 129600, or blank for none");
  const ttl = Number(input.tokenTtlSeconds.trim() || inst.settings.tokenTtlSeconds);
  if (!Number.isInteger(ttl) || ttl < 30 || ttl > 600) throw errors.badRequest("invalid_ttl", "Token lifetime must be 30 to 600 seconds");
  let claims: unknown = {};
  const raw = input.customClaims.trim();
  if (raw) {
    try {
      claims = JSON.parse(raw);
    } catch {
      throw errors.badRequest("invalid_claims", "Custom claims must be valid JSON");
    }
    if (!claims || typeof claims !== "object" || Array.isArray(claims)) throw errors.badRequest("invalid_claims", "Custom claims must be a JSON object");
  }
  const bad = validateClaims(claims as Record<string, unknown>);
  if (bad) throw errors.badRequest("invalid_claims", bad);
  const sessions = { maxLifetimeEnabled: input.maxLifetimeEnabled, inactivityTimeoutMinutes, multiSession: input.multiSession, customClaims: claims as Record<string, string> };
  await db().update(schema.instances).set({ settings: { ...inst.settings, tokenTtlSeconds: ttl, sessions }, updatedAt: new Date() }).where(eq(schema.instances.id, instanceId));
  await invalidateInstance(instanceId);
  void record(instanceId, "instance.sessions_updated", { actor: { type: "developer", id: userId }, data: { ...sessions, tokenTtlSeconds: ttl } });
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
    smsConfigured: await smsConfigured(),
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
    return { provider: p, label: labelFor(p, r?.settings), configured: !!r, enabled: !!r?.enabled, clientId: r?.clientId ?? null, settings: (r?.settings ?? {}) as ProviderSettings, redirectUri: callbackUrl(p) };
  });
}

export async function saveProvider(
  userId: string,
  instanceId: string,
  provider: string,
  input: { clientId: string; clientSecret: string; enabled: boolean; settings?: Record<string, unknown> },
) {
  await ownedInstance(userId, instanceId);
  if (!isProvider(provider)) throw errors.notFound("Unknown provider");
  const cfg = z
    .object({ clientId: z.string().trim().min(1).max(256), clientSecret: z.string().min(1).max(4096), enabled: z.boolean() })
    .parse(input);
  const settings = parseSettings(provider, input.settings, cfg.clientSecret);
  await setProviderConfig(instanceId, provider, { ...cfg, settings });
  void record(instanceId, "social_provider.saved", { actor: { type: "developer", id: userId }, target: provider, data: { enabled: cfg.enabled } });
}

export async function setProviderEnabled(userId: string, instanceId: string, provider: string, enabled: boolean) {
  await ownedInstance(userId, instanceId);
  if (!isProvider(provider)) throw errors.notFound("Unknown provider");
  await db()
    .update(schema.oauthProviders)
    .set({ enabled, updatedAt: new Date() })
    .where(and(eq(schema.oauthProviders.instanceId, instanceId), eq(schema.oauthProviders.provider, provider)));
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
    lockedUntil: (u as { lockedUntil?: string | null }).lockedUntil ?? null,
    deletionScheduledAt: (u as { deletionScheduledAt?: string | null }).deletionScheduledAt ?? null,
    lastSignInAt: u!.lastSignInAt,
    createdAt: u!.createdAt,
  }));
}

export async function banUser(userId: string, instanceId: string, targetId: string, banned: boolean) {
  await ownedInstance(userId, instanceId);
  await setBanned(instanceId, targetId, banned);
  void record(instanceId, banned ? "user.banned" : "user.unbanned", { actor: { type: "developer", id: userId }, target: targetId });
}

export async function unlockUserFromDashboard(userId: string, instanceId: string, targetId: string) {
  const inst = await ownedInstance(userId, instanceId);
  await unlockUser(inst, targetId, { type: "developer", id: userId, reason: "admin" });
}

export async function cancelDeletionFromDashboard(userId: string, instanceId: string, targetId: string) {
  const inst = await ownedInstance(userId, instanceId);
  await cancelDeletion(inst, targetId, { type: "developer", id: userId });
}

// ---------- Organization roles ----------

export async function rolesFor(userId: string, instanceId: string) {
  await ownedInstance(userId, instanceId);
  return listRoles(instanceId);
}

const permList = (raw: string) => raw.split(/[\s,]+/).map((p) => p.trim()).filter(Boolean);

export async function saveRoleFor(userId: string, instanceId: string, input: { key: string; name: string; description: string; permissions: string; isNew: boolean }) {
  const inst = await ownedInstance(userId, instanceId);
  await requireFeature(inst.accountId, "organization_settings");
  const actor = { type: "developer" as const, id: userId };
  const permissions = permList(input.permissions);
  if (input.isNew) await createRole(inst, roleInput.parse({ key: input.key, name: input.name, description: input.description || null, permissions }), actor);
  else await updateRole(inst, input.key, roleUpdate.parse({ name: input.name, description: input.description || null, permissions }), actor);
}

export async function deleteRoleFor(userId: string, instanceId: string, key: string) {
  const inst = await ownedInstance(userId, instanceId);
  await requireFeature(inst.accountId, "organization_settings");
  await deleteRole(inst, key, { type: "developer", id: userId });
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

// ---------- Email templates ----------

export async function templatesFor(userId: string, instanceId: string) {
  const inst = await ownedInstance(userId, instanceId);
  return { templates: await listTemplates(instanceId), accentColor: inst.settings.emailAccentColor ?? null, appName: inst.name };
}

export async function saveTemplateFor(userId: string, instanceId: string, kind: string, input: { subject: string; body: string }) {
  await ownedInstance(userId, instanceId);
  if (!isTemplateKind(kind)) throw errors.notFound("Unknown email");
  const t = await saveTemplate(instanceId, kind, input);
  void record(instanceId, "email_template.updated", { actor: { type: "developer", id: userId }, target: kind });
  return t;
}

export async function resetTemplateFor(userId: string, instanceId: string, kind: string) {
  await ownedInstance(userId, instanceId);
  if (!isTemplateKind(kind)) throw errors.notFound("Unknown email");
  await resetTemplate(instanceId, kind);
  void record(instanceId, "email_template.reset", { actor: { type: "developer", id: userId }, target: kind });
}

export async function setAccentColor(userId: string, instanceId: string, color: string | null) {
  const inst = await ownedInstance(userId, instanceId);
  const accent = color ? accentInput.parse(color) : undefined;
  await db().update(schema.instances).set({ settings: { ...inst.settings, emailAccentColor: accent }, updatedAt: new Date() }).where(eq(schema.instances.id, instanceId));
  await invalidateInstance(instanceId);
  void record(instanceId, "email_template.updated", { actor: { type: "developer", id: userId }, target: "branding", data: { accentColor: accent ?? null } });
}

/** Sends the saved (or default) wording, filled with sample values, to the developer's own address only. */
export async function sendTestEmail(userId: string, instanceId: string, kind: string) {
  const inst = await ownedInstance(userId, instanceId);
  if (!isTemplateKind(kind)) throw errors.notFound("Unknown email");
  const { email } = await dashboardProfile(userId);
  if (!email) throw errors.badRequest("no_email", "Your dashboard account has no email address");
  if ((await rateLimit(`${instanceId}:template_test:${userId}`, 10, 3600)) < 0) throw errors.tooMany();
  const mail = await composeEmail(inst, kind, SAMPLE_VARS(inst.name));
  await sendMail({ to: email, ...mail, subject: `[Test] ${mail.subject}`.slice(0, 200) });
  void record(instanceId, "email_template.test_sent", { actor: { type: "developer", id: userId }, target: kind });
  return email;
}

// ---------- SSO (SAML) ----------

export async function ssoFor(userId: string, instanceId: string) {
  await ownedInstance(userId, instanceId);
  const orgs = await db().select({ id: schema.organizations.id, name: schema.organizations.name }).from(schema.organizations).where(eq(schema.organizations.instanceId, instanceId)).limit(200);
  return { connections: await listConnections(instanceId), orgs };
}

export async function createSsoConnection(userId: string, instanceId: string, raw: Record<string, unknown>) {
  await ownedInstance(userId, instanceId);
  const c = await createConnection(instanceId, raw);
  void record(instanceId, "sso_connection.created", { actor: { type: "developer", id: userId }, target: c.id, data: { name: c.name, domains: c.domains } });
  return c;
}

export async function updateSsoConnection(userId: string, instanceId: string, id: string, raw: Record<string, unknown>) {
  await ownedInstance(userId, instanceId);
  const c = await updateConnection(instanceId, id, raw);
  void record(instanceId, "sso_connection.updated", { actor: { type: "developer", id: userId }, target: id });
  return c;
}

export async function createScimTokenFor(userId: string, instanceId: string, id: string) {
  await ownedInstance(userId, instanceId);
  const r = await createScimToken(instanceId, id);
  void record(instanceId, "scim_token.created", { actor: { type: "developer", id: userId }, target: id });
  return r;
}

export async function revokeScimTokenFor(userId: string, instanceId: string, id: string) {
  await ownedInstance(userId, instanceId);
  await revokeScimToken(instanceId, id);
  void record(instanceId, "scim_token.revoked", { actor: { type: "developer", id: userId }, target: id });
}

export async function deleteSsoConnection(userId: string, instanceId: string, id: string) {
  await ownedInstance(userId, instanceId);
  await deleteConnection(instanceId, id);
  void record(instanceId, "sso_connection.deleted", { actor: { type: "developer", id: userId }, target: id });
}

// ---------- Sign-up protection and two-factor policy ----------

export async function protectionFor(userId: string, instanceId: string) {
  return protectionView(await ownedInstance(userId, instanceId));
}

export async function updateProtectionFor(userId: string, instanceId: string, raw: unknown) {
  const view = await updateProtection(await ownedInstance(userId, instanceId), raw);
  void record(instanceId, "instance.settings_updated", { actor: { type: "developer", id: userId }, data: { protection: { ...view, captcha: view.captcha ? { siteKey: view.captcha.siteKey } : null } } });
  return view;
}
