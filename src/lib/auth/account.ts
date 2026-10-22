import { and, desc, eq, ne } from "drizzle-orm";
import { record, recordForUser } from "../audit";
import { z } from "zod";
import { db, schema } from "../db";
import { cache } from "../cache";
import { decryptNullable, encryptNullable, hashPassword, verifyPassword } from "../crypto";
import { errors } from "../http";
import type { Instance } from "../db/schema";
import { emit } from "../webhooks";

// ---------- Profile ----------

export const profileInput = z.object({
  firstName: z.string().trim().max(100).nullable().optional(),
  lastName: z.string().trim().max(100).nullable().optional(),
});

export async function updateProfile(userId: string, input: z.infer<typeof profileInput>) {
  const set: Record<string, unknown> = { updatedAt: new Date() };
  if (input.firstName !== undefined) set.firstNameEnc = encryptNullable(input.firstName || null, `users.first_name:${userId}`);
  if (input.lastName !== undefined) set.lastNameEnc = encryptNullable(input.lastName || null, `users.last_name:${userId}`);
  await db().update(schema.users).set(set).where(eq(schema.users.id, userId));
  void recordForUser(userId, "user.profile_updated");
}

// ---------- Password ----------

export const changePasswordInput = z.object({ currentPassword: z.string().max(256), newPassword: z.string().max(256) });

/**
 * Requires the current password, so a hijacked session can't lock the owner out.
 * Signs out every *other* session: if the password leaked, the intruder loses access.
 */
export async function changePassword(inst: Instance, userId: string, currentSessionId: string, input: z.infer<typeof changePasswordInput>) {
  if (input.newPassword.length < inst.settings.passwordMinLength)
    throw errors.badRequest("password_too_short", `Password must be at least ${inst.settings.passwordMinLength} characters`);
  const [row] = await db().select().from(schema.passwords).where(eq(schema.passwords.userId, userId));
  if (!row) throw errors.badRequest("no_password", "This account signs in without a password. Use “Forgot password” to set one");
  if (!(await verifyPassword(row.hash, input.currentPassword)))
    throw errors.badRequest("invalid_credentials", "Your current password is incorrect");
  await db().update(schema.passwords).set({ hash: await hashPassword(input.newPassword), updatedAt: new Date() }).where(eq(schema.passwords.userId, userId));
  void record(inst.id, "user.password_changed", { actor: { type: "user", id: userId }, target: userId });
  return revokeOtherSessions(userId, currentSessionId);
}

// ---------- Sessions ----------

/** Turns a user-agent string into "Chrome on macOS". Deliberately coarse. */
export function describeDevice(ua: string | null) {
  if (!ua) return "Unknown device";
  const browser =
    /Edg\//.test(ua) ? "Edge" : /OPR\//.test(ua) ? "Opera" : /Firefox\//.test(ua) ? "Firefox" :
    /Chrome\//.test(ua) ? "Chrome" : /Safari\//.test(ua) ? "Safari" : /node|undici/i.test(ua) ? "API client" : "Browser";
  const os =
    /iPhone|iPad/.test(ua) ? "iOS" : /Android/.test(ua) ? "Android" : /Mac OS X|Macintosh/.test(ua) ? "macOS" :
    /Windows/.test(ua) ? "Windows" : /Linux/.test(ua) ? "Linux" : null;
  return os ? `${browser} on ${os}` : browser;
}

/** Shows enough of the IP to recognise a location, not the full address. */
export function maskIp(ip: string | null) {
  if (!ip || ip === "unknown") return null;
  if (ip.includes(".")) return ip.split(".").slice(0, 2).join(".") + ".x.x";
  return ip.split(":").slice(0, 3).join(":") + ":…";
}

export async function listSessions(instanceId: string, userId: string, currentSessionId: string) {
  const rows = await db()
    .select()
    .from(schema.sessions)
    .where(and(eq(schema.sessions.userId, userId), eq(schema.sessions.instanceId, instanceId), eq(schema.sessions.status, "active")))
    .orderBy(desc(schema.sessions.lastActiveAt));
  return rows
    .filter((s) => s.expiresAt > new Date())
    .map((s) => ({
      id: s.id,
      current: s.id === currentSessionId,
      device: describeDevice(decryptNullable(s.userAgentEnc, `sessions.user_agent:${s.id}`)),
      ipHint: maskIp(decryptNullable(s.ipAddressEnc, `sessions.ip_address:${s.id}`)),
      lastActiveAt: s.lastActiveAt,
      createdAt: s.createdAt,
    }));
}

/** Users can only end their own sessions. */
export async function revokeOwnSession(instanceId: string, userId: string, sessionId: string) {
  const [row] = await db()
    .update(schema.sessions)
    .set({ status: "revoked" })
    .where(and(eq(schema.sessions.id, sessionId), eq(schema.sessions.userId, userId), eq(schema.sessions.instanceId, instanceId)))
    .returning({ h: schema.sessions.refreshTokenHash });
  if (!row) throw errors.notFound("Session not found");
  await cache().del(`sess:${row.h}`);
  void emit(instanceId, "session.revoked", { sessionId, userId });
}

export async function revokeOtherSessions(userId: string, keepSessionId: string) {
  const rows = await db()
    .update(schema.sessions)
    .set({ status: "revoked" })
    .where(and(eq(schema.sessions.userId, userId), eq(schema.sessions.status, "active"), ne(schema.sessions.id, keepSessionId)))
    .returning({ h: schema.sessions.refreshTokenHash });
  if (rows.length) await cache().del(...rows.map((r) => `sess:${r.h}`));
  return rows.length;
}

// ---------- Linked accounts ----------

export async function linkedProviders(userId: string) {
  const rows = await db()
    .select({ provider: schema.oauthAccounts.provider, createdAt: schema.oauthAccounts.createdAt })
    .from(schema.oauthAccounts)
    .where(eq(schema.oauthAccounts.userId, userId));
  return rows;
}

export async function hasPassword(userId: string) {
  const [row] = await db().select({ u: schema.passwords.userId }).from(schema.passwords).where(eq(schema.passwords.userId, userId));
  return !!row;
}
