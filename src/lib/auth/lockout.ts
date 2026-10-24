/**
 * Account lockout: progressive, per account, after repeated wrong passwords or second-factor codes.
 *
 * - Every attempt reserves a slot BEFORE the secret is checked (atomic INCR), so parallel guesses can't
 *   exceed the limit. Slots are returned only by a success. MAX_FAILURES wrong answers in a window lock the account.
 * - Lock lengths grow with each repeat: 5 min, 15 min, 1 h, 6 h, then 24 h.
 * - Counters and lock state live in Valkey under HMAC-keyed names (blind index), so the key space reveals
 *   neither user IDs nor email addresses. Real accounts are mirrored in `account_lockouts` so a locked
 *   account stays locked after a Valkey flush.
 * - Unknown emails get the same counters and the same lock (keyed by the email's blind index), so the
 *   responses are identical whether or not the account exists. Only real accounts get an email and events.
 * - Unlocking: the emailed link (single use, 24 h, only the SHA-256 is stored), an admin, or a password reset.
 */
import { and, eq, gt } from "drizzle-orm";
import { db, schema } from "../db";
import { cache, rateLimit } from "../cache";
import { blindIndex, decrypt } from "../crypto";
import { env } from "../env";
import { errors } from "../http";
import { newToken, sha256 } from "../ids";
import { record } from "../audit";
import { sendMail } from "../mail";
import { emailInTestMode } from "./test-mode";
import { composeEmail } from "../email-templates";
import { emit } from "../webhooks";
import { publishableKey } from "./instance";
import type { Instance } from "../db/schema";

export const MAX_FAILURES = 5;
export const FAILURE_WINDOW_SECONDS = 900;
/** Lock length per level, in seconds. Level 5 and above stay at 24 h. */
export const LOCK_SECONDS = [300, 900, 3600, 21_600, 86_400];
/** The level is forgotten this long after a lock ends. */
const LEVEL_MEMORY_SECONDS = 86_400;
const UNLOCK_LINK_SECONDS = 86_400;

export type Factor = "pw" | "mf";
/** What identifies the account: its user ID, or (for an address that has no account) the email's blind index. */
export type Subject = { userId: string } | { emailIndex: string };

const sub = (s: Subject) => ("userId" in s ? s.userId : `e:${s.emailIndex}`);
const K = (inst: string, s: Subject) => blindIndex(sub(s), `lock:${inst}`);
const stateKey = (k: string) => `lock:s:${k}`;
const failKey = (k: string, f: Factor) => `lock:f:${f}:${k}`;
const cleanKey = (k: string) => `lock:c:${k}`;

// A dedicated message: same text for every account, existing or not.
const lockedMessage = "Too many failed attempts. Try again later, or use the unlock link we emailed to the account owner.";
const locked = () => {
  const e = errors.tooMany().withCode("account_locked");
  e.message = lockedMessage;
  return e;
};

/** Milliseconds timestamp the lock ends at, or null. Real accounts fall back to the database when Valkey has nothing. */
async function lockedUntil(inst: Instance, s: Subject, k: string): Promise<number | null> {
  const c = cache();
  const raw = await c.hget(stateKey(k), "until");
  if (raw) {
    const t = Number(raw);
    return t > Date.now() ? t : null;
  }
  if (!("userId" in s) || (await c.exists(cleanKey(k)))) return null;
  const [row] = await db()
    .select({ until: schema.accountLockouts.lockedUntil, level: schema.accountLockouts.level })
    .from(schema.accountLockouts)
    .where(and(eq(schema.accountLockouts.userId, s.userId), eq(schema.accountLockouts.instanceId, inst.id)));
  if (row?.until && row.until.getTime() > Date.now()) {
    const ttl = Math.ceil((row.until.getTime() - Date.now()) / 1000) + LEVEL_MEMORY_SECONDS;
    await c.hset(stateKey(k), { until: String(row.until.getTime()), level: String(row.level) });
    await c.expire(stateKey(k), ttl);
    return row.until.getTime();
  }
  await c.set(cleanKey(k), "1", "EX", 3600); // checked: not locked (saves a query per attempt)
  return null;
}

/**
 * Call before checking a password or code. Throws `account_locked` when locked or out of attempts.
 * The slot is spent; call `succeeded` on success.
 */
export async function reserve(inst: Instance, s: Subject, factor: Factor) {
  const k = K(inst.id, s);
  if (await lockedUntil(inst, s, k)) throw locked();
  const f = failKey(k, factor);
  const [[, n]] = (await cache().multi().incr(f).expire(f, FAILURE_WINDOW_SECONDS, "NX").exec()) as [[null, number]];
  if (n > MAX_FAILURES) throw locked(); // raced past the lock being engaged
  return { key: k, attempt: n };
}

/** The reserved attempt was wrong. Locks the account when it was the last one allowed. */
export async function failed(inst: Instance, s: Subject, r: { key: string; attempt: number }, why: "password" | "second_factor") {
  if (r.attempt < MAX_FAILURES) return;
  await engage(inst, s, r.key, why);
}

/** Correct answer: the attempts for this factor are forgiven. */
export async function succeeded(inst: Instance, s: Subject, factor: Factor) {
  await cache().del(failKey(K(inst.id, s), factor));
}

async function engage(inst: Instance, s: Subject, k: string, why: string) {
  const c = cache();
  let level = Number((await c.hget(stateKey(k), "level")) ?? 0);
  let dbRow: { level: number; lockedUntil: Date | null } | undefined;
  if ("userId" in s) {
    [dbRow] = await db()
      .select({ level: schema.accountLockouts.level, lockedUntil: schema.accountLockouts.lockedUntil })
      .from(schema.accountLockouts)
      .where(eq(schema.accountLockouts.userId, s.userId));
    // Valkey forgot (flush): trust the database, unless the last lock ended long ago.
    if (dbRow && (!dbRow.lockedUntil || dbRow.lockedUntil.getTime() + LEVEL_MEMORY_SECONDS * 1000 > Date.now())) level = Math.max(level, dbRow.level);
  }
  level += 1;
  const secs = LOCK_SECONDS[Math.min(level, LOCK_SECONDS.length) - 1];
  const until = Date.now() + secs * 1000;
  await c.hset(stateKey(k), { until: String(until), level: String(level) });
  await c.expire(stateKey(k), secs + LEVEL_MEMORY_SECONDS);
  await c.del(failKey(k, "pw"), failKey(k, "mf"), cleanKey(k));
  if (!("userId" in s)) return; // no account: same lock, nothing to tell anyone

  const token = newToken();
  const row = {
    userId: s.userId,
    instanceId: inst.id,
    level,
    lockedAt: new Date(),
    lockedUntil: new Date(until),
    reason: why,
    unlockTokenHash: sha256(token),
    unlockExpiresAt: new Date(Date.now() + UNLOCK_LINK_SECONDS * 1000),
    updatedAt: new Date(),
  };
  await db().insert(schema.accountLockouts).values(row).onConflictDoUpdate({ target: schema.accountLockouts.userId, set: row });
  void record(inst.id, "user.locked", { actor: { type: "system" }, target: s.userId, data: { level, lockedUntil: new Date(until).toISOString(), reason: why } });
  void emit(inst.id, "user.locked", { userId: s.userId, lockedUntil: new Date(until).toISOString(), level, reason: why });
  void sendUnlockEmail(inst, s.userId, token);
}

async function primaryEmail(instanceId: string, userId: string) {
  const [row] = await db()
    .select({ id: schema.emailAddresses.id, enc: schema.emailAddresses.emailEnc })
    .from(schema.emailAddresses)
    .where(and(eq(schema.emailAddresses.userId, userId), eq(schema.emailAddresses.instanceId, instanceId)))
    .orderBy(schema.emailAddresses.isPrimary);
  return row ? decrypt(row.enc, `email_addresses.email:${row.id}`) : null;
}

async function sendUnlockEmail(inst: Instance, userId: string, token: string) {
  try {
    if ((await rateLimit(`${inst.id}:unlock_mail:${userId}`, 3, 3600)) < 0) return;
    const to = await primaryEmail(inst.id, userId);
    if (!to) return;
    // Token in the fragment (not sent to servers or logs); the landing page needs a click, so link scanners can't use it.
    const link = `${env().APP_URL}/unlock?pk=${encodeURIComponent(publishableKey(inst))}#token=${encodeURIComponent(token)}`;
    if (!emailInTestMode(inst, to)) await sendMail({ to, ...(await composeEmail(inst, "account_unlock", { link, expires_hours: String(UNLOCK_LINK_SECONDS / 3600) })) });
  } catch (e) {
    console.error("[lockout] unlock email failed", (e as Error).message);
  }
}

async function clearState(inst: Instance, userId: string, opts: { resetLevel: boolean }) {
  const c = cache();
  const k = K(inst.id, { userId });
  const wasLocked = !!(await lockedUntil(inst, { userId }, k));
  await c.del(stateKey(k), failKey(k, "pw"), failKey(k, "mf"));
  if (opts.resetLevel) await c.del(cleanKey(k));
  await c.set(cleanKey(k), "1", "EX", 3600);
  const set = { lockedUntil: null, lockedAt: null, unlockTokenHash: null, unlockExpiresAt: null, updatedAt: new Date(), ...(opts.resetLevel ? { level: 0 } : {}) };
  await db().update(schema.accountLockouts).set(set).where(and(eq(schema.accountLockouts.userId, userId), eq(schema.accountLockouts.instanceId, inst.id)));
  return wasLocked;
}

/** Admin (dashboard or backend API) or password reset. Resets the progression. Returns whether the account was locked. */
export async function unlockUser(inst: Instance, userId: string, by: { type: "developer" | "api" | "user"; id?: string; reason: string }) {
  const [u] = await db().select({ id: schema.users.id }).from(schema.users).where(and(eq(schema.users.id, userId), eq(schema.users.instanceId, inst.id)));
  if (!u) throw errors.notFound("User not found");
  const was = await clearState(inst, userId, { resetLevel: true });
  if (was) {
    void record(inst.id, "user.unlocked", { actor: { type: by.type, id: by.id }, target: userId, data: { reason: by.reason } });
    void emit(inst.id, "user.unlocked", { userId, reason: by.reason });
  }
  return was;
}

/** The emailed link. One use. Keeps the progression (a repeat attacker still escalates). */
export async function unlockWithToken(inst: Instance, token: string) {
  const [row] = await db()
    .update(schema.accountLockouts)
    .set({ unlockTokenHash: null, unlockExpiresAt: null })
    .where(and(eq(schema.accountLockouts.instanceId, inst.id), eq(schema.accountLockouts.unlockTokenHash, sha256(token)), gt(schema.accountLockouts.unlockExpiresAt, new Date())))
    .returning({ userId: schema.accountLockouts.userId });
  if (!row) throw errors.badRequest("invalid_unlock_link", "This unlock link has expired or was already used");
  const was = await clearState(inst, row.userId, { resetLevel: false });
  if (was) {
    void record(inst.id, "user.unlocked", { actor: { type: "user", id: row.userId }, target: row.userId, data: { reason: "email_link" } });
    void emit(inst.id, "user.unlocked", { userId: row.userId, reason: "email_link" });
  }
}

/** For the user object in the backend API and dashboard. */
export async function lockStatus(instanceId: string, userId: string): Promise<string | null> {
  const [row] = await db()
    .select({ until: schema.accountLockouts.lockedUntil })
    .from(schema.accountLockouts)
    .where(and(eq(schema.accountLockouts.userId, userId), eq(schema.accountLockouts.instanceId, instanceId)));
  return row?.until && row.until.getTime() > Date.now() ? row.until.toISOString() : null;
}
