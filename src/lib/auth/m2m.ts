/**
 * Machine-to-machine auth: per-instance clients using the OAuth 2.0 client credentials grant (RFC 6749 4.4).
 * Secrets are random and shown once; only a SHA-256 is stored and compared in constant time. Tokens are short-lived
 * JWTs signed with the instance's key, so any service can verify them against the existing JWKS.
 */
import { and, count, desc, eq } from "drizzle-orm";
import { z } from "zod";
import { db, schema } from "../db";
import { rateLimit } from "../cache";
import { errors } from "../http";
import { newId, newToken, safeEqual, sha256 } from "../ids";
import { record, type Actor } from "../audit";
import { mintMachineToken } from "./keys";
import { getInstance } from "./instance";

export const MAX_CLIENTS = 20;
export const MAX_SCOPES = 25;
export const DEFAULT_TTL = 300;
export const MAX_TTL = 3600;

export const scopeString = z.string().trim().regex(/^[a-z][a-z0-9_.:-]{0,63}$/, "Scopes are lowercase, like read:invoices");
export const scopeList = z.array(scopeString).max(MAX_SCOPES).transform((a) => [...new Set(a)]);

export const clientInput = z.object({
  name: z.string().trim().min(1).max(60),
  scopes: scopeList.default([]),
  tokenTtlSeconds: z.number().int().min(30).max(MAX_TTL).optional(),
}).strict();
export const clientUpdate = clientInput.partial().strict();

type Row = typeof schema.m2mClients.$inferSelect;
export const clientView = (c: Row) => ({
  id: c.id, // the client_id
  name: c.name,
  secretPrefix: c.secretPrefix,
  scopes: c.scopes,
  tokenTtlSeconds: c.tokenTtlSeconds,
  rotating: !!c.prevSecretHash && !!c.prevSecretExpiresAt && c.prevSecretExpiresAt > new Date(),
  lastUsedAt: c.lastUsedAt,
  createdAt: c.createdAt,
});

const newSecret = () => `ms_${newToken(32)}`;

export async function listClients(instanceId: string) {
  const rows = await db().select().from(schema.m2mClients).where(eq(schema.m2mClients.instanceId, instanceId)).orderBy(desc(schema.m2mClients.createdAt));
  return rows.map(clientView);
}

async function owned(instanceId: string, id: string) {
  const [row] = await db().select().from(schema.m2mClients).where(and(eq(schema.m2mClients.id, id), eq(schema.m2mClients.instanceId, instanceId)));
  if (!row) throw errors.notFound("Client not found");
  return row;
}
export const getClient = async (instanceId: string, id: string) => clientView(await owned(instanceId, id));

/** Returns the secret once. */
export async function createClient(instanceId: string, raw: unknown, actor: Actor) {
  const input = clientInput.parse(raw);
  const [{ n }] = await db().select({ n: count() }).from(schema.m2mClients).where(eq(schema.m2mClients.instanceId, instanceId));
  if (n >= MAX_CLIENTS) throw errors.limitReached(`Up to ${MAX_CLIENTS} machine clients`);
  const secret = newSecret();
  const [row] = await db().insert(schema.m2mClients).values({
    id: newId("m2m"), instanceId, name: input.name, scopes: input.scopes, tokenTtlSeconds: input.tokenTtlSeconds ?? DEFAULT_TTL,
    secretHash: sha256(secret), secretPrefix: secret.slice(0, 9),
  }).returning();
  void record(instanceId, "m2m_client.created", { actor, target: row.id, data: { name: row.name, scopes: row.scopes } });
  return { ...clientView(row), clientSecret: secret };
}

export async function updateClient(instanceId: string, id: string, raw: unknown, actor: Actor) {
  const input = clientUpdate.parse(raw);
  await owned(instanceId, id);
  const [row] = await db().update(schema.m2mClients).set({ ...input, updatedAt: new Date() }).where(and(eq(schema.m2mClients.id, id), eq(schema.m2mClients.instanceId, instanceId))).returning();
  void record(instanceId, "m2m_client.updated", { actor, target: id, data: input });
  return clientView(row);
}

export async function deleteClient(instanceId: string, id: string, actor: Actor) {
  await owned(instanceId, id);
  await db().delete(schema.m2mClients).where(and(eq(schema.m2mClients.id, id), eq(schema.m2mClients.instanceId, instanceId)));
  void record(instanceId, "m2m_client.deleted", { actor, target: id });
  return { id, deleted: true as const };
}

/** New secret; the old one keeps working for `graceMinutes` (0 to 1440) so deployments can switch over. */
export async function rotateSecret(instanceId: string, id: string, graceMinutes: number, actor: Actor) {
  const grace = z.number().int().min(0).max(1440).parse(graceMinutes);
  const old = await owned(instanceId, id);
  const secret = newSecret();
  const [row] = await db().update(schema.m2mClients).set({
    secretHash: sha256(secret), secretPrefix: secret.slice(0, 9),
    prevSecretHash: grace ? old.secretHash : null, prevSecretExpiresAt: grace ? new Date(Date.now() + grace * 60_000) : null, updatedAt: new Date(),
  }).where(eq(schema.m2mClients.id, id)).returning();
  void record(instanceId, "m2m_client.secret_rotated", { actor, target: id, data: { graceMinutes: grace } });
  return { ...clientView(row), clientSecret: secret };
}

// ---------- Token endpoint ----------

export class OAuthError extends Error {
  constructor(public status: number, public code: "invalid_request" | "invalid_client" | "invalid_scope" | "unsupported_grant_type" | "temporarily_unavailable", message: string) {
    super(message);
  }
}

const DUMMY = sha256("dummy-client-secret");
const TOUCH_MS = 5 * 60_000;

/** Authenticates the client and issues a token for the requested scopes (default: all of the client's scopes). */
export async function issueMachineToken(input: { clientId?: string; clientSecret?: string; grantType?: string; scope?: string }, ip: string) {
  if (input.grantType !== "client_credentials") throw new OAuthError(400, "unsupported_grant_type", "Only client_credentials is supported");
  const { clientId, clientSecret } = input;
  if (!clientId || !clientSecret || clientId.length > 100 || clientSecret.length > 200) throw new OAuthError(401, "invalid_client", "Client authentication failed");
  if ((await rateLimit(`m2m:ip:${ip}`, 120, 60)) < 0) throw new OAuthError(429, "temporarily_unavailable", "Too many requests");
  if ((await rateLimit(`m2m:client:${clientId}`, 600, 60)) < 0) throw new OAuthError(429, "temporarily_unavailable", "Too many requests");

  const [c] = /^m2m_[0-9a-z]{22}$/.test(clientId) ? await db().select().from(schema.m2mClients).where(eq(schema.m2mClients.id, clientId)) : [];
  const given = sha256(clientSecret);
  const okCurrent = safeEqual(given, c?.secretHash ?? DUMMY);
  const okPrev = !!c?.prevSecretHash && !!c.prevSecretExpiresAt && c.prevSecretExpiresAt > new Date() && safeEqual(given, c.prevSecretHash);
  if (!c || !(okCurrent || okPrev)) {
    // Failures are throttled per source and client, so guessing is slow but a stranger can't lock the real service out.
    if ((await rateLimit(`m2m:fail:${ip}:${clientId}`, 10, 300)) < 0) throw new OAuthError(429, "temporarily_unavailable", "Too many failed attempts");
    throw new OAuthError(401, "invalid_client", "Client authentication failed");
  }

  const requested = input.scope?.trim() ? [...new Set(input.scope.trim().split(/\s+/))] : c.scopes;
  const bad = requested.filter((s) => !c.scopes.includes(s));
  if (bad.length) throw new OAuthError(400, "invalid_scope", "The client isn't allowed that scope");
  if (!(await getInstance(c.instanceId))) throw new OAuthError(401, "invalid_client", "Client authentication failed");

  if (!c.lastUsedAt || Date.now() - c.lastUsedAt.getTime() > TOUCH_MS)
    void db().update(schema.m2mClients).set({ lastUsedAt: new Date() }).where(eq(schema.m2mClients.id, c.id)).catch(() => undefined);
  const access_token = await mintMachineToken(c.instanceId, { clientId: c.id, scope: requested }, c.tokenTtlSeconds);
  return { access_token, token_type: "Bearer" as const, expires_in: c.tokenTtlSeconds, scope: requested.join(" ") };
}
