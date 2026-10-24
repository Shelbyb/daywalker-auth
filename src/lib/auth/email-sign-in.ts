/**
 * Passwordless sign-in by email: one email carries both a 6-digit code and a one-time link.
 *
 * - Only an HMAC of the code and a SHA-256 of the link token are stored (Valkey, 10 minutes).
 * - Either one works once; using one burns the other. Asking again replaces both.
 * - 5 wrong codes burn the attempt. Sends are throttled per address, silently.
 * - The response never says whether the email has an account.
 * - The link token travels in the URL fragment, so it isn't sent to servers or logged, and the
 *   landing page needs a click: mail scanners that prefetch links can't use it up.
 */
import { randomInt } from "node:crypto";
import { and, eq } from "drizzle-orm";
import { z } from "zod";
import { db, schema } from "../db";
import { cache, rateLimit } from "../cache";
import { blindIndex, decrypt, encrypt } from "../crypto";
import { env } from "../env";
import { errors } from "../http";
import { newToken, safeEqual, sha256 } from "../ids";
import { sendMail } from "../mail";
import { composeEmail } from "../email-templates";
import { record } from "../audit";
import { publishableKey } from "./instance";
import type { Instance } from "../db/schema";
import { TEST_CODE, emailInTestMode } from "./test-mode";
import { assertSsoNotRequired, assertSsoNotRequiredForUser } from "./sso-policy";

const TTL = 600;
const MAX_ATTEMPTS = 5;
const normEmail = z.string().trim().toLowerCase().email().max(254);
export const sendInput = z.object({ email: normEmail, redirectUrl: z.string().max(2048).optional(), captchaToken: z.string().max(2048).optional() });
export const verifyInput = z.object({ email: normEmail, code: z.string().trim().max(10) });
export const linkInput = z.object({ token: z.string().min(20).max(100) });

const emailIndex = (instanceId: string, email: string) => blindIndex(email, `email:${instanceId}`);
const codeKey = (instanceId: string, idx: string) => `esi:${instanceId}:${idx}`;
const linkKey = (token: string) => `esil:${sha256(token)}`;
const codeMac = (code: string, idx: string) => blindIndex(code, `email_sign_in:${idx}`);

export const emailCodeEnabled = (inst: Instance) => inst.settings.emailCodeSignIn === true;
function assertEnabled(inst: Instance) {
  if (!emailCodeEnabled(inst)) throw errors.badRequest("email_code_disabled", "Email sign-in isn't turned on for this app");
}

async function accountFor(instanceId: string, idx: string) {
  const [row] = await db()
    .select({ emailId: schema.emailAddresses.id, userId: schema.users.id, banned: schema.users.banned })
    .from(schema.emailAddresses)
    .innerJoin(schema.users, eq(schema.users.id, schema.emailAddresses.userId))
    .where(and(eq(schema.emailAddresses.instanceId, instanceId), eq(schema.emailAddresses.emailIndex, idx)));
  return row ?? null;
}

/** Sends the code and link if the address has an account. Resolves the same way either way. */
export async function sendSignInEmail(inst: Instance, email: string, redirect: string | null) {
  assertEnabled(inst);
  const test = emailInTestMode(inst, email); // throws for test addresses on production
  await assertSsoNotRequired(inst.id, email); // depends on the domain only, so it reveals nothing about accounts
  const idx = emailIndex(inst.id, email);
  if ((await rateLimit(`${inst.id}:esi_send:${idx}`, 5, 3600)) < 0) return;
  const acct = await accountFor(inst.id, idx);
  if (!acct) return;
  const code = test ? TEST_CODE : randomInt(0, 1_000_000).toString().padStart(6, "0");
  const token = newToken(32);
  const k = codeKey(inst.id, idx);
  const old = await cache().hget(k, "l");
  if (old) await cache().del(`esil:${old}`); // a new email replaces the old link too
  await cache().hset(k, { h: codeMac(code, idx), l: sha256(token), n: "0", r: redirect ?? "" });
  await cache().expire(k, TTL);
  await cache().set(linkKey(token), encrypt(JSON.stringify({ i: inst.id, x: idx }), "esi_link"), "EX", TTL);
  const link = `${env().APP_URL}/magic-link?pk=${encodeURIComponent(publishableKey(inst))}#token=${encodeURIComponent(token)}`;
  if (!test) await sendMail({ to: email, ...(await composeEmail(inst, "sign_in", { code, link, expires_minutes: "10" })) });
}

async function finish(inst: Instance, idx: string, method: "email_code" | "magic_link") {
  const k = codeKey(inst.id, idx);
  const [redirect, l] = await cache().hmget(k, "r", "l");
  if (l) await cache().del(`esil:${l}`);
  // Deleting the record is the lock: of two simultaneous uses (code + link, or a double submit), only one wins.
  if ((await cache().del(k)) !== 1) throw errors.badRequest("invalid_code", "That code is incorrect or has expired");
  const acct = await accountFor(inst.id, idx);
  if (!acct) throw errors.badRequest("invalid_code", "That code is incorrect or has expired");
  await assertSsoNotRequiredForUser(inst.id, acct.userId);
  if (acct.banned) {
    void record(inst.id, "user.sign_in_blocked", { target: acct.userId, data: { reason: "suspended", method } });
    throw errors.forbidden("This account is suspended");
  }
  // Getting the email proves control of the inbox.
  await db().update(schema.emailAddresses).set({ verifiedAt: new Date() }).where(eq(schema.emailAddresses.id, acct.emailId));
  return { userId: acct.userId, redirect: redirect || null, method };
}

export async function verifySignInCode(inst: Instance, email: string, code: string) {
  assertEnabled(inst);
  const idx = emailIndex(inst.id, email);
  const k = codeKey(inst.id, idx);
  const attempts = await cache().hincrby(k, "n", 1);
  const stored = await cache().hget(k, "h");
  const bad = () => errors.badRequest("invalid_code", "That code is incorrect or has expired");
  if (!stored) {
    await cache().del(k);
    throw bad();
  }
  if (attempts > MAX_ATTEMPTS) {
    const l = await cache().hget(k, "l");
    await cache().del(k, ...(l ? [`esil:${l}`] : []));
    throw bad();
  }
  if (!/^\d{6}$/.test(code) || !safeEqual(stored, codeMac(code, idx))) {
    const acct = await accountFor(inst.id, idx);
    if (acct) void record(inst.id, "user.sign_in_failed", { target: acct.userId, data: { reason: "wrong_email_code", attempt: attempts } });
    throw bad();
  }
  return finish(inst, idx, "email_code");
}

export async function useMagicLink(inst: Instance, token: string) {
  assertEnabled(inst);
  const raw = await cache().getdel(linkKey(token));
  const expired = () => errors.badRequest("invalid_link", "This sign-in link has expired or was already used. Request a new one");
  if (!raw) throw expired();
  const { i, x } = JSON.parse(decrypt(raw, "esi_link")) as { i: string; x: string };
  if (i !== inst.id) throw expired();
  const l = await cache().hget(codeKey(inst.id, x), "l");
  if (!l || !safeEqual(l, sha256(token))) throw expired(); // superseded by a newer email
  return finish(inst, x, "magic_link");
}
