/**
 * Passkey-first sign-up: an account with no password, created with a passkey and a verified email.
 *
 *   1. start     the person gives an email (and name). We email a 6-digit code. The answer is the same
 *                whether or not the address already has an account, so this can't be used to find out.
 *   2. verify    they enter the code. This proves they control the inbox, and gives them a single-use
 *                token plus WebAuthn options for a brand-new user ID. Nothing is created yet.
 *   3. complete  the browser's attestation is checked against that challenge. Only now are the user,
 *                the (already verified) email and the passkey written, in one transaction.
 *
 * Unfinished attempts leave nothing behind but short-lived Valkey entries. The same rules as a password
 * sign-up apply: required SSO, domain rules, terms, the human check. Opt-in per app (`passkeySignUp`).
 */
import { z } from "zod";
import { and, eq } from "drizzle-orm";
import type { RegistrationResponseJSON } from "@simplewebauthn/server";
import { db, schema } from "../db";
import { cache, rateLimit } from "../cache";
import { blindIndex, decrypt, encrypt, encryptNullable } from "../crypto";
import { errors } from "../http";
import { newId, newToken, sha256 } from "../ids";
import { sendMail } from "../mail";
import { composeEmail } from "../email-templates";
import { record } from "../audit";
import { emit } from "../webhooks";
import { assertSsoNotRequired } from "./sso-policy";
import { assertEmailAllowed } from "./signup-protection";
import { legalOf, acceptanceRow } from "./legal";
import { issueCode, consumeCode } from "./codes";
import { newRegistrationOptions, checkRegistration, passkeyName } from "./passkeys";
import type { Instance } from "../db/schema";

const PENDING_TTL = 600;
const TOKEN_TTL = 300;
const email = z.string().trim().toLowerCase().email().max(254);

export const startInput = z.object({
  email,
  firstName: z.string().trim().max(100).optional(),
  lastName: z.string().trim().max(100).optional(),
  legalAccepted: z.boolean().optional(),
  captchaToken: z.string().max(2048).optional(),
});
export const verifyInput = z.object({ email, code: z.string().trim().max(10) });

export const passkeySignUpEnabled = (inst: Instance) => inst.settings.passkeySignUp === true;
const assertEnabled = (inst: Instance) => {
  if (!passkeySignUpEnabled(inst)) throw errors.badRequest("passkey_signup_disabled", "Signing up with a passkey isn't turned on for this app");
};

const emailIndex = (instanceId: string, e: string) => blindIndex(e, `email:${instanceId}`);
const subject = (inst: Instance, idx: string) => `${inst.id}:${idx}`;
const profileKey = (inst: Instance, idx: string) => `pks:p:${subject(inst, idx)}`;
const tokenKey = (token: string) => `pks:t:${sha256(token)}`;

type Profile = { firstName?: string; lastName?: string; legal: boolean };

/** Sends a code to a new address. Resolves identically for addresses that already have an account. */
export async function startPasskeySignUp(inst: Instance, input: z.infer<typeof startInput>) {
  assertEnabled(inst);
  await assertSsoNotRequired(inst.id, input.email);
  assertEmailAllowed(inst, input.email);
  if (legalOf(inst).required && input.legalAccepted !== true) throw errors.badRequest("legal_required", "Please accept the terms to create an account");
  const idx = emailIndex(inst.id, input.email);
  if ((await rateLimit(`${inst.id}:pks_send:${idx}`, 5, 3600)) < 0) return; // silent, like other email senders
  const [taken] = await db().select({ id: schema.emailAddresses.id }).from(schema.emailAddresses).where(and(eq(schema.emailAddresses.instanceId, inst.id), eq(schema.emailAddresses.emailIndex, idx)));
  if (taken) return;
  const profile: Profile = { firstName: input.firstName, lastName: input.lastName, legal: input.legalAccepted === true };
  await cache().set(profileKey(inst, idx), encrypt(JSON.stringify(profile), `pks_profile:${subject(inst, idx)}`), "EX", PENDING_TTL);
  const code = await issueCode("passkey_signup", subject(inst, idx));
  await sendMail({ to: input.email, ...(await composeEmail(inst, "verify_email", { code, expires_minutes: "10" })) });
}

/** Checks the emailed code and hands back a single-use token and WebAuthn options for the new account. */
export async function verifyPasskeySignUpCode(inst: Instance, input: z.infer<typeof verifyInput>) {
  assertEnabled(inst);
  const idx = emailIndex(inst.id, input.email);
  const bad = () => errors.badRequest("invalid_code", "That code is incorrect or has expired");
  if (!(await consumeCode("passkey_signup", subject(inst, idx), input.code))) throw bad();
  const raw = await cache().getdel(profileKey(inst, idx));
  if (!raw) throw bad();
  const profile = JSON.parse(decrypt(raw, `pks_profile:${subject(inst, idx)}`)) as Profile;
  const userId = newId("user");
  const name = [profile.firstName, profile.lastName].filter(Boolean).join(" ");
  const options = await newRegistrationOptions(inst, userId, input.email, name);
  const token = newToken(32);
  await cache().set(tokenKey(token), encrypt(JSON.stringify({ i: inst.id, u: userId, e: input.email, c: options.challenge, p: profile }), "pks_token"), "EX", TOKEN_TTL);
  return { token, options };
}

/** Creates the account. The email is verified (the code proved it) and the passkey is its only credential. */
export async function completePasskeySignUp(inst: Instance, token: string, response: RegistrationResponseJSON, label?: string) {
  assertEnabled(inst);
  const raw = await cache().getdel(tokenKey(token)); // single use, whatever happens next
  const expired = () => errors.badRequest("challenge_expired", "Sign-up timed out. Please start again");
  if (!raw) throw expired();
  const t = JSON.parse(decrypt(raw, "pks_token")) as { i: string; u: string; e: string; c: string; p: Profile };
  if (t.i !== inst.id) throw expired();
  // Re-checked: settings or the address may have changed since the code was sent.
  await assertSsoNotRequired(inst.id, t.e);
  assertEmailAllowed(inst, t.e);
  if (legalOf(inst).required && !t.p.legal) throw errors.badRequest("legal_required", "Please accept the terms to create an account");
  const cred = await checkRegistration(inst, response, t.c);
  const userId = t.u;
  try {
    await db().transaction(async (tx) => {
      await tx.insert(schema.users).values({
        id: userId,
        instanceId: inst.id,
        firstNameEnc: encryptNullable(t.p.firstName, `users.first_name:${userId}`),
        lastNameEnc: encryptNullable(t.p.lastName, `users.last_name:${userId}`),
      });
      const emailId = newId("email");
      await tx.insert(schema.emailAddresses).values({
        id: emailId,
        instanceId: inst.id,
        userId,
        emailEnc: encrypt(t.e, `email_addresses.email:${emailId}`),
        emailIndex: emailIndex(inst.id, t.e),
        isPrimary: true,
        verifiedAt: new Date(),
      });
      await tx.insert(schema.passkeys).values({ id: newId("pk"), instanceId: inst.id, userId, ...cred, name: passkeyName(label, cred.backedUp) });
      if (t.p.legal) await tx.insert(schema.legalAcceptances).values(acceptanceRow(inst, userId, "passkey"));
    });
  } catch (e) {
    const code = (e as { code?: string; cause?: { code?: string } }).cause?.code ?? (e as { code?: string }).code;
    if (code === "23505") throw errors.conflict("email_taken", "That email address is already in use");
    throw e;
  }
  void emit(inst.id, "user.created", { userId, email: t.e });
  void record(inst.id, "user.signed_up", { actor: { type: "user", id: userId }, target: userId, data: { method: "passkey" } });
  return userId;
}
