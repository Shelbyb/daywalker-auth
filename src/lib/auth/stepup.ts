/**
 * Step-up authentication. Every session remembers when its person last proved a first factor
 * (password, passkey, emailed code) and a second factor (authenticator, text, backup code, security
 * key, user-verified passkey). Session tokens carry both ages (`fva`, `auth_time`), so an app's
 * server can demand "proved it in the last 5 minutes" before a sensitive action and send the user
 * through `session/reverify` when they haven't.
 *
 * Wrong answers count toward account lockout exactly like sign-in.
 */
import { z } from "zod";
import { eq } from "drizzle-orm";
import type { AuthenticationResponseJSON } from "@simplewebauthn/server";
import { db, schema } from "../db";
import { record } from "../audit";
import { errors } from "../http";
import { verifyPassword } from "../crypto";
import * as lockout from "./lockout";
import { twoFactorMethods, verifySecondFactor, confirmed, hasTwoFactor } from "./mfa";
import { markVerified, issueToken } from "./sessions";
import { authenticationOptions, verifyAuthentication } from "./passkeys";
import { reauthRequirements, sendReauthCode } from "./account-deletion";
import { consumeCode } from "./codes";
import type { Instance } from "../db/schema";

export const reverifyInput = z.discriminatedUnion("factor", [
  z.object({ factor: z.literal("password"), password: z.string().min(1).max(256) }),
  z.object({ factor: z.literal("code"), code: z.string().trim().min(6).max(20), method: z.enum(["totp", "sms"]).optional() }),
  z.object({ factor: z.literal("email_code"), code: z.string().trim().min(4).max(10) }),
  z.object({ factor: z.literal("security_key") }),
]);
export type ReverifyInput = z.infer<typeof reverifyInput>;
type Sess = { id: string; userId: string; impersonatorId?: string | null };

function notForImpersonation(s: Sess) {
  if (s.impersonatorId) throw errors.forbidden("Not available while support is signed in as this user").withCode("impersonation_forbidden");
}

/** What this person can use to prove themselves right now, so a prompt shows only real choices. */
export async function reverifyOptions(userId: string) {
  const need = await reauthRequirements(userId);
  const m = await twoFactorMethods(userId);
  const [pk] = await db().select({ id: schema.passkeys.id }).from(schema.passkeys).where(eq(schema.passkeys.userId, userId)).limit(1);
  return { password: need.password, passkey: !!pk, totp: m.totp, sms: m.sms, securityKey: m.securityKeys > 0, backupCodes: m.backupCodes > 0, emailCode: need.emailCode };
}

export const sendReverifyEmailCode = sendReauthCode;

/** Proves one factor for this session. Returns a fresh session token that carries the new ages. */
export async function reverify(inst: Instance, s: Sess, input: ReverifyInput, azp?: string, refreshToken?: string) {
  notForImpersonation(s);
  const subject = { userId: s.userId };
  let first = false;
  let second = false;
  if (input.factor === "password") {
    const slot = await lockout.reserve(inst, subject, "pw");
    const [row] = await db().select({ hash: schema.passwords.hash }).from(schema.passwords).where(eq(schema.passwords.userId, s.userId));
    if (!row || !(await verifyPassword(row.hash, input.password))) {
      await lockout.failed(inst, subject, slot, "password");
      void record(inst.id, "user.sign_in_failed", { target: s.userId, data: { reason: "wrong_password", purpose: "reverify" } });
      throw errors.badRequest("invalid_credentials", "Your password is incorrect");
    }
    await lockout.succeeded(inst, subject, "pw");
    first = true;
  } else if (input.factor === "code") {
    if (!(await hasTwoFactor(s.userId))) throw errors.badRequest("no_second_factor", "This account has no second factor set up");
    const slot = await lockout.reserve(inst, subject, "mf");
    if (!(await verifySecondFactor(s.userId, input.code, input.method))) {
      await lockout.failed(inst, subject, slot, "second_factor");
      void record(inst.id, "user.two_factor_failed", { target: s.userId, data: { purpose: "reverify" } });
      throw errors.badRequest("invalid_code", "That code is incorrect");
    }
    await lockout.succeeded(inst, subject, "mf");
    second = true;
  } else if (input.factor === "email_code") {
    if (!(await reauthRequirements(s.userId)).emailCode) throw errors.badRequest("not_available", "This account confirms with its password or second factor");
    if (!(await consumeCode("reauth", s.userId, input.code))) throw errors.badRequest("invalid_code", "That code is incorrect or has expired");
    first = true;
  } else {
    // A security key touched earlier in this session (mfa/security_keys/confirm); single use, two minutes.
    if (!(await confirmed(s.userId, s.id))) throw errors.badRequest("security_key_required", "Touch your security key first");
    second = true;
  }
  await finish(inst, s, { first, second }, input.factor);
  return token(inst, refreshToken, azp);
}

export const passkeyReverifyOptions = (inst: Instance, s: Sess) => {
  notForImpersonation(s);
  return authenticationOptions(inst, s.userId);
};

/** A user-verified passkey is a device plus a biometric or PIN, so it refreshes both factors. */
export async function reverifyWithPasskey(inst: Instance, s: Sess, response: AuthenticationResponseJSON, azp?: string, refreshToken?: string) {
  notForImpersonation(s);
  const owner = await verifyAuthentication(inst, response);
  if (owner !== s.userId) throw errors.badRequest("passkey_invalid", "That passkey couldn't be verified");
  await finish(inst, s, { first: true, second: true }, "passkey");
  return token(inst, refreshToken, azp);
}

async function finish(inst: Instance, s: Sess, kinds: { first: boolean; second: boolean }, method: string) {
  await markVerified(s.id, inst.id, kinds);
  void record(inst.id, "user.reverified", { actor: { type: "user", id: s.userId }, target: s.userId, data: { sessionId: s.id, method } });
}

async function token(inst: Instance, refreshToken: string | undefined, azp?: string) {
  const { jwt } = await issueToken(inst, refreshToken, azp);
  return { verified: true as const, jwt };
}
