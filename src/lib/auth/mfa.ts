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
import { rateLimit } from "../cache";
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from "@simplewebauthn/server";
import {
  countSecurityKeys,
  deleteSecurityKeyRow,
  securityKeyAuthenticationOptions,
  securityKeyRegistrationOptions,
  verifySecurityKeyAuthentication,
  verifySecurityKeyRegistration,
} from "./security-keys";
import { checkSmsCode, maskPhone, normalizePhone, phoneInAllowedCountry, sendSmsCode, smsConfigured } from "../sms";

const secretCtx = (userId: string) => `mfa_totp.secret:${userId}`;

// ---------- Status ----------

async function totpOn(userId: string) {
  const [row] = await db()
    .select({ userId: schema.mfaTotp.userId })
    .from(schema.mfaTotp)
    .where(and(eq(schema.mfaTotp.userId, userId), isNotNull(schema.mfaTotp.verifiedAt)));
  return !!row;
}

const phoneCtx = (userId: string) => `mfa_sms.phone:${userId}`;
async function smsPhone(userId: string, verified = true) {
  const [row] = await db()
    .select()
    .from(schema.mfaSms)
    .where(and(eq(schema.mfaSms.userId, userId), verified ? isNotNull(schema.mfaSms.verifiedAt) : isNull(schema.mfaSms.verifiedAt)));
  return row ? decrypt(row.phoneEnc, phoneCtx(userId)) : null;
}

/** On when an authenticator app, a verified phone or a security key is set up. */
import * as lockout from "./lockout";
import { getInstance } from "./instance";
async function lockoutInstance(id: string) {
  const inst = await getInstance(id);
  if (!inst) throw errors.unauthorized();
  return inst;
}

export async function hasTwoFactor(userId: string) {
  return (await totpOn(userId)) || (await smsPhone(userId)) !== null || (await countSecurityKeys(userId)) > 0;
}

/** Which second factors this user can use right now (for the sign-in and account screens). */
export async function twoFactorMethods(userId: string) {
  const phone = (await smsConfigured()) ? await smsPhone(userId) : null;
  return { totp: await totpOn(userId), sms: phone ? maskPhone(phone) : null, securityKeys: await countSecurityKeys(userId), backupCodes: await remainingBackupCodes(userId) };
}

// ---------- Enrollment ----------

/** Step 1: create (or replace an unconfirmed) secret. Returns what the authenticator app needs. */
export async function startTotpEnrollment(inst: Instance, userId: string, accountLabel: string, currentCode?: string, sessionId?: string) {
  if (await totpOn(userId)) throw errors.conflict("already_enabled", "An authenticator app is already set up");
  // Adding a factor to an account that already has one needs a current code: otherwise a stolen
  // session could add the attacker's own authenticator and keep access.
  if ((await hasTwoFactor(userId)) && !(await confirmed(userId, sessionId, currentCode)))
    throw errors.badRequest("code_required", "Confirm with a current two-factor code or a security key to add an authenticator app");
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
  const hadSms = (await smsPhone(userId)) !== null || (await countSecurityKeys(userId)) > 0;
  await db().update(schema.mfaTotp).set({ verifiedAt: new Date() }).where(eq(schema.mfaTotp.userId, userId));
  void recordForUser(userId, "user.two_factor_enabled", { data: { method: "totp" } });
  // Backup codes are made when two-factor is first turned on; adding a second method keeps them.
  return hadSms && (await remainingBackupCodes(userId)) > 0 ? [] : regenerateBackupCodes(userId);
}

/** Turning 2FA off (or new backup codes) requires a current code: a stolen session alone isn't enough. */
export async function disableTwoFactor(userId: string, code: string | undefined, sessionId?: string) {
  if (!(await confirmed(userId, sessionId, code))) throw errors.badRequest("invalid_code", "That code is incorrect");
  await db().delete(schema.mfaTotp).where(eq(schema.mfaTotp.userId, userId));
  await db().delete(schema.mfaSms).where(eq(schema.mfaSms.userId, userId));
  await db().delete(schema.mfaSecurityKeys).where(eq(schema.mfaSecurityKeys.userId, userId));
  await db().delete(schema.backupCodes).where(eq(schema.backupCodes.userId, userId));
  void recordForUser(userId, "user.two_factor_disabled");
}

export async function rotateBackupCodes(userId: string, code: string | undefined, sessionId?: string) {
  if (!(await hasTwoFactor(userId))) throw errors.badRequest("not_enabled", "Two-factor authentication is off");
  if (!(await confirmed(userId, sessionId, code))) throw errors.badRequest("invalid_code", "That code is incorrect");
  return regenerateBackupCodes(userId);
}

/** Admin escape hatch (backend API) for users who lost their device and their backup codes. */
export async function adminResetTwoFactor(userId: string) {
  await db().delete(schema.mfaTotp).where(eq(schema.mfaTotp.userId, userId));
  await db().delete(schema.mfaSms).where(eq(schema.mfaSms.userId, userId));
  await db().delete(schema.mfaSecurityKeys).where(eq(schema.mfaSecurityKeys.userId, userId));
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

/**
 * Confirms a sensitive change: a current code, or (no code) a security key touch made earlier in
 * this same session. The key proof is stored for two minutes, tied to the session, and used once.
 */
export async function confirmed(userId: string, sessionId: string | undefined, code?: string) {
  if (code) return verifySecondFactor(userId, code);
  if (!sessionId) return false;
  return (await cache().getdel(`stepup:${sessionId}`)) === userId;
}

/** Step 1 of confirming with a key: the browser prompt options (only this person's keys can answer). */
export const startKeyConfirmation = (userId: string) => securityKeyAuthenticationOptions(userId);

/** Step 2: a valid answer opens a two-minute, one-use window for this session. */
export async function confirmWithSecurityKey(inst: Instance, userId: string, sessionId: string, response: AuthenticationResponseJSON) {
  if (!(await verifySecurityKeyAuthentication(inst, userId, response))) {
    void record(inst.id, "user.two_factor_failed", { target: userId, data: { method: "security_key", purpose: "confirm" } });
    throw errors.badRequest("security_key_invalid", "That security key couldn't be verified");
  }
  await cache().set(`stepup:${sessionId}`, userId, "EX", 120);
}

/**
 * Accepts a 6-digit authenticator code, a texted code, or a backup code. A 6-digit code is checked
 * against the authenticator app unless `method` is "sms" (or the user has only SMS set up).
 */
export async function verifySecondFactor(userId: string, code: string, method?: "totp" | "sms") {
  const c = code.trim();
  if (/^\d{6}$/.test(c)) {
    const [row] = await db()
      .select()
      .from(schema.mfaTotp)
      .where(and(eq(schema.mfaTotp.userId, userId), isNotNull(schema.mfaTotp.verifiedAt)));
    const viaSms = async () => {
      const phone = (await smsConfigured()) ? await smsPhone(userId) : null;
      return phone ? checkSmsCode(phone, c) : false;
    };
    if (method === "sms" || (!row && method !== "totp")) return viaSms();
    if (row && (await consumeTotp(userId, decrypt(row.secretEnc, secretCtx(userId)), c))) return true;
    // Not an authenticator code: if we texted this user recently, it may be the texted one.
    return method !== "totp" && (await cache().exists(`sms:sent:${userId}`)) === 1 ? viaSms() : false;
  }
  return consumeBackupCode(userId, c);
}

// ---------- SMS ----------

export const smsAllowed = async (inst: Instance) => inst.settings.smsSecondFactor === true && (await smsConfigured());

/** Limits per user, per phone number and per instance-wide IP bucket, so texts can't be used to run up a bill. */
async function smsLimit(inst: Instance, userId: string, phone: string) {
  const idx = blindIndex(phone, `phone:${inst.id}`);
  if ((await rateLimit(`${inst.id}:sms_user:${userId}`, 5, 3600)) < 0 || (await rateLimit(`${inst.id}:sms_phone:${idx}`, 5, 3600)) < 0)
    throw errors.tooMany();
  return idx;
}

/** Step 1 of adding a phone: text a code to it. If two-factor is already on, a current code is required. */
export async function startSmsEnrollment(inst: Instance, userId: string, rawPhone: string, currentCode?: string, sessionId?: string) {
  if (!(await smsAllowed(inst))) throw errors.badRequest("sms_disabled", "SMS two-factor isn't available for this app");
  const phone = normalizePhone(rawPhone);
  if (!phone) throw errors.badRequest("invalid_phone", "Enter the number in international format, like +1 415 555 0100");
  // Only for new numbers: people who already added a phone keep it, so narrowing the list never locks anyone out.
  if (!phoneInAllowedCountry(phone, inst.settings.smsCountries)) throw errors.badRequest("sms_country_not_allowed", "Text messages aren't available for numbers in that country");
  if ((await smsPhone(userId)) !== null) throw errors.conflict("already_enabled", "A phone is already set up. Remove it first to use a different one");
  if ((await hasTwoFactor(userId)) && !(await confirmed(userId, sessionId, currentCode)))
    throw errors.badRequest("code_required", "Confirm with a current two-factor code or a security key to add a phone");
  const phoneIndex = await smsLimit(inst, userId, phone);
  const phoneEnc = encrypt(phone, phoneCtx(userId));
  await db().insert(schema.mfaSms).values({ userId, phoneEnc, phoneIndex }).onConflictDoUpdate({ target: schema.mfaSms.userId, set: { phoneEnc, phoneIndex, verifiedAt: null } });
  if (!(await sendSmsCode(phone))) throw errors.badRequest("sms_failed", "We couldn't text that number. Check it and try again");
  return { phone: maskPhone(phone) };
}

/** Step 2: the user types the texted code. Returns backup codes when this turns two-factor on. */
export async function confirmSmsEnrollment(userId: string, code: string) {
  const phone = await smsPhone(userId, false);
  if (!phone) throw errors.badRequest("no_pending_enrollment", "Add a phone number first");
  if (!(await checkSmsCode(phone, code.trim()))) throw errors.badRequest("invalid_code", "That code is incorrect or has expired");
  const hadTotp = (await totpOn(userId)) || (await countSecurityKeys(userId)) > 0;
  await db().update(schema.mfaSms).set({ verifiedAt: new Date() }).where(eq(schema.mfaSms.userId, userId));
  void recordForUser(userId, "user.two_factor_enabled", { data: { method: "sms", phone: maskPhone(phone) } });
  return hadTotp && (await remainingBackupCodes(userId)) > 0 ? [] : regenerateBackupCodes(userId);
}

/** Texts a code to the user's verified phone (to sign in, or to confirm a change on the account page). */
export async function sendSmsChallenge(inst: Instance, userId: string) {
  if (!(await smsConfigured())) throw errors.badRequest("sms_disabled", "SMS isn't available");
  const phone = await smsPhone(userId);
  if (!phone) throw errors.badRequest("no_phone", "No phone is set up for two-factor");
  await smsLimit(inst, userId, phone);
  if (!(await sendSmsCode(phone))) throw errors.badRequest("sms_failed", "We couldn't send a text right now. Try another method");
  await cache().set(`sms:sent:${userId}`, "1", "EX", 600);
  return { phone: maskPhone(phone) };
}

/** Removing the phone needs a current code. If it was the only factor, two-factor turns off. */
export async function removeSms(userId: string, code: string | undefined, sessionId?: string) {
  if ((await smsPhone(userId)) === null && (await smsPhone(userId, false)) === null) throw errors.notFound("No phone is set up");
  if (await hasTwoFactor(userId)) {
    if (!(await confirmed(userId, sessionId, code))) throw errors.badRequest("invalid_code", "That code is incorrect");
  }
  await db().delete(schema.mfaSms).where(eq(schema.mfaSms.userId, userId));
  if (!(await hasTwoFactor(userId))) await db().delete(schema.backupCodes).where(eq(schema.backupCodes.userId, userId));
  void recordForUser(userId, "user.two_factor_disabled", { data: { method: "sms" } });
}

// ---------- Security keys ----------

/** Step 1 of adding a key. If two-factor is already on, a current code is required (same rule as every other factor). */
export async function startSecurityKeyEnrollment(inst: Instance, userId: string, sessionId: string, currentCode?: string) {
  if ((await hasTwoFactor(userId)) && !(await confirmed(userId, sessionId, currentCode)))
    throw errors.badRequest("code_required", "Confirm with a current two-factor code or a security key to add a security key");
  return securityKeyRegistrationOptions(inst, userId, sessionId);
}

/** Step 2: the key's answer. Returns backup codes when this is what turns two-factor on. */
export async function confirmSecurityKeyEnrollment(inst: Instance, userId: string, sessionId: string, response: RegistrationResponseJSON, label?: string) {
  const hadOther = await hasTwoFactor(userId);
  const id = await verifySecurityKeyRegistration(inst, userId, sessionId, response, label);
  void recordForUser(userId, "user.two_factor_enabled", { data: { method: "security_key", keyId: id } });
  return { id, backupCodes: hadOther && (await remainingBackupCodes(userId)) > 0 ? [] : await regenerateBackupCodes(userId) };
}

/** Removing a key needs a current code. If it was the last factor, two-factor turns off. */
export async function removeSecurityKey(userId: string, id: string, code: string | undefined, sessionId?: string) {
  if (!(await confirmed(userId, sessionId, code))) throw errors.badRequest("invalid_code", "That code is incorrect");
  await deleteSecurityKeyRow(userId, id);
  if (!(await hasTwoFactor(userId))) await db().delete(schema.backupCodes).where(eq(schema.backupCodes.userId, userId));
  void recordForUser(userId, "user.two_factor_disabled", { data: { method: "security_key", keyId: id } });
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
export async function completePendingSecondFactor(instanceId: string, token: string | undefined, code: string, method?: "totp" | "sms") {
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
  const inst = await lockoutInstance(instanceId);
  const slot = await lockout.reserve(inst, { userId: pending.userId }, "mf");
  if (!(await verifySecondFactor(pending.userId, code, method))) {
    await lockout.failed(inst, { userId: pending.userId }, slot, "second_factor");
    void record(instanceId, "user.two_factor_failed", { target: pending.userId, data: { attempt: attempts } });
    throw errors.badRequest("invalid_code", "That code is incorrect");
  }
  await lockout.succeeded(inst, { userId: pending.userId }, "mf");
  await cache().del(key);
  return pending.userId;
}

/** Same attempt limit as codes, for a security key's answer. */
export async function completePendingWithSecurityKey(inst: Instance, token: string | undefined, response: AuthenticationResponseJSON) {
  if (!token) throw errors.unauthorized("Your sign-in attempt expired. Please sign in again");
  const key = pendingKey(token);
  const attempts = await cache().hincrby(key, "n", 1);
  const raw = await cache().hget(key, "d");
  if (!raw || attempts > MAX_ATTEMPTS) {
    await cache().del(key);
    throw errors.unauthorized("Your sign-in attempt expired. Please sign in again");
  }
  const pending = JSON.parse(decrypt(raw, "2fa_pending")) as { instanceId: string; userId: string };
  if (pending.instanceId !== inst.id) throw errors.unauthorized();
  const slot = await lockout.reserve(inst, { userId: pending.userId }, "mf");
  if (!(await verifySecurityKeyAuthentication(inst, pending.userId, response))) {
    await lockout.failed(inst, { userId: pending.userId }, slot, "second_factor");
    void record(inst.id, "user.two_factor_failed", { target: pending.userId, data: { attempt: attempts, method: "security_key" } });
    throw errors.badRequest("security_key_invalid", "That security key couldn't be verified");
  }
  await lockout.succeeded(inst, { userId: pending.userId }, "mf");
  await cache().del(key);
  return pending.userId;
}

/** The pending sign-in's user, without using up an attempt (for "text me a code" and the method list). */
export async function pendingUser(instanceId: string, token: string | undefined) {
  if (!token) return null;
  const raw = await cache().hget(pendingKey(token), "d");
  if (!raw) return null;
  const p = JSON.parse(decrypt(raw, "2fa_pending")) as { instanceId: string; userId: string };
  return p.instanceId === instanceId ? p.userId : null;
}
