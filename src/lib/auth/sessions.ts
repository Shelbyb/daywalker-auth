import { and, eq } from "drizzle-orm";
import { db, schema } from "../db";
import { cache } from "../cache";
import { newId, newToken, sha256 } from "../ids";
import { errors } from "../http";
import { mintSessionToken } from "./keys";
import { encryptNullable } from "../crypto";
import type { Instance } from "../db/schema";

/** Cookie per instance so multiple apps on one auth origin don't collide. */
export const refreshCookieName = (instanceId: string) => `__dw_rt_${instanceId.slice(4, 14)}`;

type CachedSession = { id: string; userId: string; status: string; expiresAt: string; createdAt?: string };
const sessKey = (refreshHash: string) => `sess:${refreshHash}`;

export async function createSession(
  inst: Instance,
  userId: string,
  meta: { userAgent?: string | null; ip?: string | null },
) {
  const refreshToken = newToken();
  const expiresAt = new Date(Date.now() + inst.settings.sessionLifetimeDays * 86_400_000);
  const id = newId("sess");
  await db().insert(schema.sessions).values({
    id,
    instanceId: inst.id,
    userId,
    refreshTokenHash: sha256(refreshToken),
    userAgentEnc: encryptNullable(meta.userAgent?.slice(0, 512), `sessions.user_agent:${id}`),
    ipAddressEnc: encryptNullable(meta.ip, `sessions.ip_address:${id}`),
    expiresAt,
  });
  await db().update(schema.users).set({ lastSignInAt: new Date() }).where(eq(schema.users.id, userId));
  return { id, refreshToken, expiresAt };
}

/**
 * Hot path: called every ~50s per active tab. Valkey absorbs the read; Postgres is hit
 * on a miss. Revocation deletes the cache entry, so it takes effect on the next refresh.
 */
export async function resolveSession(instanceId: string, refreshToken: string) {
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
      };
      await cache().set(sessKey(h), JSON.stringify(s), "EX", 300);
    }
  }
  if (!s || s.status !== "active" || new Date(s.expiresAt) <= new Date()) return null;
  // Throttle last-active writes to once a minute per session.
  if (await cache().set(`sess:touch:${s.id}`, "1", "EX", 60, "NX")) {
    await db().update(schema.sessions).set({ lastActiveAt: new Date() }).where(eq(schema.sessions.id, s.id));
  }
  return s;
}

export async function issueToken(inst: Instance, refreshToken: string | undefined, azp?: string) {
  if (!refreshToken) throw errors.unauthorized();
  const s = await resolveSession(inst.id, refreshToken);
  if (!s) throw errors.unauthorized("Session is no longer active");
  const jwt = await mintSessionToken(inst.id, { sub: s.userId, sid: s.id, azp }, inst.settings.tokenTtlSeconds);
  return { jwt, sessionId: s.id, userId: s.userId };
}

export async function endSession(instanceId: string, refreshToken: string, status: "ended" | "revoked" = "ended") {
  const h = sha256(refreshToken);
  await db()
    .update(schema.sessions)
    .set({ status })
    .where(and(eq(schema.sessions.refreshTokenHash, h), eq(schema.sessions.instanceId, instanceId)));
  await cache().del(sessKey(h));
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
}
