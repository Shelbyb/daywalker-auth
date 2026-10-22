import { randomInt } from "node:crypto";
import { record, recordForUser } from "../audit";
import { and, eq, isNull, isNotNull } from "drizzle-orm";
import { db, schema } from "../db";
import { cache } from "../cache";
import { blindIndex, decrypt, encrypt } from "../crypto";
import { newId, newToken, sha256 } from "../ids";
import { errors } from "../http";
import { newTotpSecret, matchTotp, otpauthUri } from "./totp";
import type { Instance } from "../db/schema";

const secretCtx = (userId: string) => `mfa_totp.secret:${userId}`;

// ---------- Status ----------

export async function hasTwoFactor(userId: string) {
  const [row] = await db()
    .select({ userId: schema.mfaTotp.userId })
    .from(schema.mfaTotp)
    .where(and(eq(schema.mfaTotp.userId, userId), isNotNull(schema.mfaTotp.verifiedAt)));
  return !!row;
}

// ---------- Enrollment ----------

/** Step 1: create (or replace an unconfirmed) secret. Returns what the authenticator app needs. */
export async function startTotpEnrollment(inst: Instance, userId: string, accountLabel: string) {
  if (await hasTwoFactor(userId)) throw errors.conflict("already_enabled", "Two-factor authentication is already on");
  const secret = newTotpSecret();
  const secretEnc = encrypt(secret, secretCtx(userId));
  await db()
    .insert(schema.mfaTotp)
    .values({ userId, secretEnc })
    .onConflictDoUpdate({ target: schema.mfaTotp.userId, set: { secretEnc, verifiedAt: null } });
  return { secret, uri: otpauthUri(secret, inst.name, accountLabel) };
}

/** Step 2: the user proves their app works. Turns 2FA on and returns backup codes (shown once). */
export async function confirmTotpEnrollment(userId: string, code: string) {
  const [row] = await db()
    .select()
    .from(schema.mfaTotp)
    .where(and(eq(schema.mfaTotp.userId, userId), isNull(schema.mfaTotp.verifiedAt)));
  if (!row) throw errors.badRequest("no_pending_enrollment", "Start two-factor setup first");
  if (!(await consumeTotp(userId, decrypt(row.secretEnc, secretCtx(userId)), code)))
    throw errors.badRequest("invalid_code", "That code is incorrect. Check your device's clock and try again");
  await db().update(schema.mfaTotp).set({ verifiedAt: new Date() }).where(eq(schema.mfaTotp.userId, userId));
  void recordForUser(userId, "user.two_factor_enabled");
  return regenerateBackupCodes(userId);
}

/** Turning 2FA off (or new backup codes) requires a current code: a stolen session alone isn't enough. */
export async function disableTwoFactor(userId: string, code: string) {
  if (!(await verifySecondFactor(userId, code))) throw errors.badRequest("invalid_code", "That code is incorrect");
  await db().delete(schema.mfaTotp).where(eq(schema.mfaTotp.userId, userId));
  await db().delete(schema.backupCodes).where(eq(schema.backupCodes.userId, userId));
  void recordForUser(userId, "user.two_factor_disabled");
}

export async function rotateBackupCodes(userId: string, code: string) {
  if (!(await hasTwoFactor(userId))) throw errors.badRequest("not_enabled", "Two-factor authentication is off");
  if (!(await verifySecondFactor(userId, code))) throw errors.badRequest("invalid_code", "That code is incorrect");
  return regenerateBackupCodes(userId);
}

/** Admin escape hatch (backend API) for users who lost their device and their backup codes. */
export async function adminResetTwoFactor(userId: string) {
  await db().delete(schema.mfaTotp).where(eq(schema.mfaTotp.userId, userId));
  await db().delete(schema.backupCodes).where(eq(schema.backupCodes.userId, userId));
  void recordForUser(userId, "user.two_factor_reset", { actor: { type: "api" } });
}

// ---------- Backup codes ----------

// No 0/o, 1/l/i: easy to read off paper.
const BC_ALPHABET = "23456789abcdefghjkmnpqrstuvwxyz";
const normalizeBackup = (c: string) => c.toLowerCase().replace(/[^a-z0-9]/g, "");
const backupHash = (userId: string, code: string) => blindIndex(normalizeBackup(code), `backup:${userId}`);

async function regenerateBackupCodes(userId: string) {
  const codes = Array.from({ length: 10 }, () => {
    let s = "";
    for (let i = 0; i < 10; i++) s += BC_ALPHABET[randomInt(BC_ALPHABET.length)]; // ~49 bits each
    return `${s.slice(0, 5)}-${s.slice(5)}`;
  });
  await db().transaction(async (tx) => {
    await tx.delete(schema.backupCodes).where(eq(schema.backupCodes.userId, userId));
    await tx.insert(schema.backupCodes).values(codes.map((c) => ({ id: newId("bc"), userId, codeHash: backupHash(userId, c) })));
  });
  return codes;
}

async function consumeBackupCode(userId: string, code: string) {
  if (normalizeBackup(code).length !== 10) return false;
  // Conditional update = atomic single use, even under concurrent requests.
  const used = await db()
    .update(schema.backupCodes)
    .set({ usedAt: new Date() })
    .where(and(eq(schema.backupCodes.userId, userId), eq(schema.backupCodes.codeHash, backupHash(userId, code)), isNull(schema.backupCodes.usedAt)))
    .returning({ id: schema.backupCodes.id });
  return used.length === 1;
}

export async function remainingBackupCodes(userId: string) {
  const rows = await db()
    .select({ id: schema.backupCodes.id })
    .from(schema.backupCodes)
    .where(and(eq(schema.backupCodes.userId, userId), isNull(schema.backupCodes.usedAt)));
  return rows.length;
}

// ---------- Verification ----------

/** A TOTP code is valid once: the accepted time step is recorded, so a shoulder-surfed code can't be replayed. */
async function consumeTotp(userId: string, secret: string, code: string) {
  const counter = matchTotp(secret, code.trim());
  if (counter === null) return false;
  return (await cache().set(`totp:used:${userId}:${counter}`, "1", "EX", 120, "NX")) === "OK";
}

/** Accepts a 6-digit authenticator code or a backup code. */
export async function verifySecondFactor(userId: string, code: string) {
  const c = code.trim();
  if (/^\d{6}$/.test(c)) {
    const [row] = await db()
      .select()
      .from(schema.mfaTotp)
      .where(and(eq(schema.mfaTotp.userId, userId), isNotNull(schema.mfaTotp.verifiedAt)));
    return row ? consumeTotp(userId, decrypt(row.secretEnc, secretCtx(userId)), c) : false;
  }
  return consumeBackupCode(userId, c);
}

// ---------- Pending second factor (between password/OAuth and session) ----------

export const twoFactorCookieName = (instanceId: string) => `__dw_2fa_${instanceId.slice(4, 14)}`;
const PENDING_TTL = 300;
const MAX_ATTEMPTS = 5;
const pendingKey = (token: string) => `2fa:${sha256(token)}`;

/** First factor passed. Returns an opaque token for an HttpOnly cookie; no session exists yet. */
export async function createPendingSecondFactor(instanceId: string, userId: string) {
  const token = newToken();
  await cache().hset(pendingKey(token), { d: encrypt(JSON.stringify({ instanceId, userId }), "2fa_pending"), n: "0" });
  await cache().expire(pendingKey(token), PENDING_TTL);
  return { token, maxAge: PENDING_TTL };
}

/** Returns the user ID once the second factor checks out. 5 wrong codes and the attempt is void. */
export async function completePendingSecondFactor(instanceId: string, token: string | undefined, code: string) {
  if (!token) throw errors.unauthorized("Your sign-in attempt expired. Please sign in again");
  const key = pendingKey(token);
  const attempts = await cache().hincrby(key, "n", 1);
  const raw = await cache().hget(key, "d");
  if (!raw || attempts > MAX_ATTEMPTS) {
    await cache().del(key);
    throw errors.unauthorized("Your sign-in attempt expired. Please sign in again");
  }
  const pending = JSON.parse(decrypt(raw, "2fa_pending")) as { instanceId: string; userId: string };
  if (pending.instanceId !== instanceId) throw errors.unauthorized();
  if (!(await verifySecondFactor(pending.userId, code))) {
    void record(instanceId, "user.two_factor_failed", { target: pending.userId, data: { attempt: attempts } });
    throw errors.badRequest("invalid_code", "That code is incorrect");
  }
  await cache().del(key);
  return pending.userId;
}
