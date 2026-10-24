/**
 * API keys that an app's own users and organizations hold (to call the app's API). Different from the secret keys
 * (sk_...) developers use against this service. A key is shown once; only its SHA-256 is stored, with a short prefix
 * for display. The app verifies a key by asking this service (`POST /v1/api_keys/verify`) so a revoked key stops working at once.
 */
import { and, count, desc, eq, isNull } from "drizzle-orm";
import { z } from "zod";
import { db, schema } from "../db";
import { errors } from "../http";
import { newId, newToken, sha256 } from "../ids";
import { record, type Actor } from "../audit";
import { scopeList } from "./m2m";
import { requirePermission } from "./orgs";
import type { Instance } from "../db/schema";

export const DEFAULT_MAX_PER_SUBJECT = 10;
const TOUCH_MS = 5 * 60_000;

export type ApiKeySettings = { enabled: boolean; maxPerSubject: number; maxExpiryDays: number | null; allowedScopes: string[] };
export function apiKeySettings(inst: Pick<Instance, "settings">): ApiKeySettings {
  const s = inst.settings?.apiKeys ?? {};
  return { enabled: s.enabled ?? false, maxPerSubject: s.maxPerSubject ?? DEFAULT_MAX_PER_SUBJECT, maxExpiryDays: s.maxExpiryDays ?? null, allowedScopes: s.allowedScopes ?? [] };
}
export const settingsInput = z.object({
  enabled: z.boolean(),
  maxPerSubject: z.number().int().min(1).max(25),
  maxExpiryDays: z.number().int().min(1).max(3650).nullable(),
  allowedScopes: scopeList,
}).partial().strict();

export const keyInput = z.object({
  name: z.string().trim().min(1).max(60),
  scopes: scopeList.default([]),
  expiresInDays: z.number().int().min(1).max(3650).nullish(),
  userId: z.string().max(100).optional(),
  orgId: z.string().max(100).optional(),
}).strict();

type Row = typeof schema.userApiKeys.$inferSelect;
export const keyView = (k: Row) => ({
  id: k.id,
  name: k.name,
  prefix: k.keyPrefix,
  scopes: k.scopes,
  subject: k.userId ? { type: "user" as const, id: k.userId } : { type: "org" as const, id: k.orgId! },
  createdBy: k.createdBy,
  expiresAt: k.expiresAt,
  lastUsedAt: k.lastUsedAt,
  revokedAt: k.revokedAt,
  createdAt: k.createdAt,
});

const newKey = (inst: Instance) => `ak_${inst.environment === "production" ? "live" : "test"}_${newToken(32)}`;

/** Creates a key for a user or organization. `limits` are the self-service rules; the backend API passes none. */
async function create(inst: Instance, subject: { userId?: string; orgId?: string }, input: z.infer<typeof keyInput>, createdBy: string | null, actor: Actor, limits?: ApiKeySettings) {
  if (!!subject.userId === !!subject.orgId) throw errors.badRequest("invalid_subject", "Give exactly one of userId or orgId");
  const sc = subject.userId ? eq(schema.userApiKeys.userId, subject.userId) : eq(schema.userApiKeys.orgId, subject.orgId!);
  const [{ n }] = await db().select({ n: count() }).from(schema.userApiKeys).where(and(eq(schema.userApiKeys.instanceId, inst.id), sc, isNull(schema.userApiKeys.revokedAt)));
  const max = limits?.maxPerSubject ?? 25;
  if (n >= max) throw errors.limitReached(`Up to ${max} active API keys. Revoke one first`);
  if (limits) {
    const bad = input.scopes.filter((s) => !limits.allowedScopes.includes(s));
    if (bad.length) throw errors.badRequest("scope_not_allowed", `Scopes not available for API keys: ${bad.join(", ")}`);
    if (limits.maxExpiryDays && (!input.expiresInDays || input.expiresInDays > limits.maxExpiryDays)) throw errors.badRequest("expiry_required", `Keys must expire within ${limits.maxExpiryDays} days`);
  }
  const key = newKey(inst);
  const [row] = await db().insert(schema.userApiKeys).values({
    id: newId("uak"), instanceId: inst.id, userId: subject.userId ?? null, orgId: subject.orgId ?? null, createdBy, name: input.name,
    keyHash: sha256(key), keyPrefix: key.slice(0, 12), scopes: input.scopes,
    expiresAt: input.expiresInDays ? new Date(Date.now() + input.expiresInDays * 86_400_000) : null,
  }).returning();
  void record(inst.id, "user_api_key.created", { actor, target: row.id, data: { subject: keyView(row).subject, scopes: row.scopes, prefix: row.keyPrefix } });
  return { ...keyView(row), key }; // the only time the key is shown
}

async function subjectExists(inst: Instance, s: { userId?: string; orgId?: string }) {
  if (s.userId) {
    const [u] = await db().select({ id: schema.users.id }).from(schema.users).where(and(eq(schema.users.id, s.userId), eq(schema.users.instanceId, inst.id)));
    if (!u) throw errors.notFound("User not found");
  } else if (s.orgId) {
    const [o] = await db().select({ id: schema.organizations.id }).from(schema.organizations).where(and(eq(schema.organizations.id, s.orgId), eq(schema.organizations.instanceId, inst.id)));
    if (!o) throw errors.notFound("Organization not found");
  }
}

/** Backend API: any user or organization of the instance. */
export async function createForSubject(inst: Instance, raw: unknown, actor: Actor) {
  const input = keyInput.parse(raw);
  await subjectExists(inst, input);
  return create(inst, input, input, null, actor);
}

/** Frontend API: the signed-in user's own keys, or an organization's (needs org:manage). Off unless the app enabled it. */
export async function createForSession(inst: Instance, userId: string, raw: unknown) {
  const settings = apiKeySettings(inst);
  if (!settings.enabled) throw errors.forbidden("API keys aren't enabled for this app").withCode("api_keys_disabled");
  const input = keyInput.parse(raw);
  if (input.userId) throw errors.badRequest("invalid_subject", "Use orgId or leave it out");
  if (input.orgId) await requirePermission(inst.id, input.orgId, userId, "org:manage");
  return create(inst, input.orgId ? { orgId: input.orgId } : { userId }, input, userId, { type: "user", id: userId }, settings);
}

export async function listKeys(inst: Instance, q: { userId?: string; orgId?: string; includeRevoked?: boolean }) {
  const conds = [eq(schema.userApiKeys.instanceId, inst.id)];
  if (q.userId) conds.push(eq(schema.userApiKeys.userId, q.userId));
  if (q.orgId) conds.push(eq(schema.userApiKeys.orgId, q.orgId));
  if (!q.includeRevoked) conds.push(isNull(schema.userApiKeys.revokedAt));
  const rows = await db().select().from(schema.userApiKeys).where(and(...conds)).orderBy(desc(schema.userApiKeys.createdAt)).limit(200);
  return rows.map(keyView);
}

export async function listForSession(inst: Instance, userId: string, orgId?: string) {
  if (!apiKeySettings(inst).enabled) throw errors.forbidden("API keys aren't enabled for this app").withCode("api_keys_disabled");
  if (orgId) {
    await requirePermission(inst.id, orgId, userId, "org:manage");
    return listKeys(inst, { orgId });
  }
  return listKeys(inst, { userId });
}

async function find(inst: Instance, id: string) {
  const [row] = await db().select().from(schema.userApiKeys).where(and(eq(schema.userApiKeys.id, id), eq(schema.userApiKeys.instanceId, inst.id)));
  if (!row) throw errors.notFound("API key not found");
  return row;
}

async function revoke(inst: Instance, row: Row, actor: Actor) {
  const [r] = await db().update(schema.userApiKeys).set({ revokedAt: row.revokedAt ?? new Date() }).where(eq(schema.userApiKeys.id, row.id)).returning();
  if (!row.revokedAt) void record(inst.id, "user_api_key.revoked", { actor, target: row.id, data: { prefix: row.keyPrefix } });
  return keyView(r);
}
export async function revokeByBackend(inst: Instance, id: string, actor: Actor) {
  return revoke(inst, await find(inst, id), actor);
}
export async function getByBackend(inst: Instance, id: string) {
  return keyView(await find(inst, id));
}
export async function revokeForSession(inst: Instance, userId: string, id: string) {
  const row = await find(inst, id);
  if (row.orgId) await requirePermission(inst.id, row.orgId, userId, "org:manage");
  else if (row.userId !== userId) throw errors.notFound("API key not found"); // someone else's key: don't reveal it exists
  return revoke(inst, row, { type: "user", id: userId });
}

/** Checks a key presented to the app's API. Revoked, expired or foreign keys, and keys of banned users, are invalid. */
export async function verifyKey(inst: Instance, key: string) {
  if (typeof key !== "string" || key.length > 200 || !/^ak_(test|live)_[A-Za-z0-9_-]+$/.test(key)) return { valid: false as const };
  const [row] = await db().select().from(schema.userApiKeys).where(and(eq(schema.userApiKeys.keyHash, sha256(key)), eq(schema.userApiKeys.instanceId, inst.id)));
  if (!row || row.revokedAt || (row.expiresAt && row.expiresAt <= new Date())) return { valid: false as const };
  if (row.userId) {
    const [u] = await db().select({ banned: schema.users.banned, del: schema.users.deletionRequestedAt }).from(schema.users).where(eq(schema.users.id, row.userId));
    if (!u || u.banned || u.del) return { valid: false as const };
  }
  if (!row.lastUsedAt || Date.now() - row.lastUsedAt.getTime() > TOUCH_MS)
    void db().update(schema.userApiKeys).set({ lastUsedAt: new Date() }).where(eq(schema.userApiKeys.id, row.id)).catch(() => undefined);
  return { valid: true as const, ...keyView(row) };
}
