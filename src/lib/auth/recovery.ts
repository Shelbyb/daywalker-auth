import { and, eq } from "drizzle-orm";
import { composeEmail } from "../email-templates";
import { assertNotBreached } from "./breach";
import { record } from "../audit";
import { z } from "zod";
import { db, schema } from "../db";
import { cache, rateLimit } from "../cache";
import { blindIndex, decrypt, hashPassword } from "../crypto";
import { errors } from "../http";
import { sendMail } from "../mail";
import { issueCode, consumeCode } from "./codes";
import type { Instance } from "../db/schema";
import { unlockUser } from "./lockout";
import { assertSsoNotRequired } from "./sso-policy";

const emailIndex = (instanceId: string, email: string) => blindIndex(email, `email:${instanceId}`);
const normEmail = z.string().trim().toLowerCase().email().max(254);

export const verifyInput = z.object({ code: z.string().trim() });
export const forgotInput = z.object({ email: normEmail, captchaToken: z.string().max(2048).optional() });
export const resetInput = z.object({ email: normEmail, code: z.string().trim(), password: z.string().max(256) });

async function primaryEmail(instanceId: string, userId: string) {
  const [row] = await db()
    .select()
    .from(schema.emailAddresses)
    .where(and(eq(schema.emailAddresses.userId, userId), eq(schema.emailAddresses.instanceId, instanceId), eq(schema.emailAddresses.isPrimary, true)));
  if (!row) throw errors.notFound("No email address on this account");
  return { id: row.id, verified: !!row.verifiedAt, email: decrypt(row.emailEnc, `email_addresses.email:${row.id}`) };
}

/** Sends a verification code to the signed-in user's primary email. */
export async function sendVerification(inst: Instance, userId: string) {
  const e = await primaryEmail(inst.id, userId);
  if (e.verified) throw errors.badRequest("already_verified", "This email address is already verified");
  if ((await rateLimit(`${inst.id}:verify_send:${userId}`, 5, 3600)) < 0) throw errors.tooMany();
  const code = await issueCode("verify_email", e.id);
  await sendMail({ to: e.email, ...(await composeEmail(inst, "verify_email", { code, expires_minutes: "10" })) });
}

export async function verifyEmail(inst: Instance, userId: string, code: string) {
  const e = await primaryEmail(inst.id, userId);
  if (e.verified) return;
  if (!(await consumeCode("verify_email", e.id, code))) throw errors.badRequest("invalid_code", "That code is incorrect or has expired");
  await db().update(schema.emailAddresses).set({ verifiedAt: new Date() }).where(eq(schema.emailAddresses.id, e.id));
}

/**
 * Always resolves the same way whether or not the account exists, so this endpoint
 * can't be used to discover registered emails. Throttled per address and silently.
 */
export async function forgotPassword(inst: Instance, email: string) {
  await assertSsoNotRequired(inst.id, email);
  const idx = emailIndex(inst.id, email);
  if ((await rateLimit(`${inst.id}:reset_send:${idx}`, 5, 3600)) < 0) return;
  const [row] = await db()
    .select({ id: schema.emailAddresses.id })
    .from(schema.emailAddresses)
    .where(and(eq(schema.emailAddresses.instanceId, inst.id), eq(schema.emailAddresses.emailIndex, idx)));
  if (!row) return;
  const code = await issueCode("reset_password", idx);
  await sendMail({ to: email, ...(await composeEmail(inst, "reset_password", { code, expires_minutes: "10" })) });
}

/**
 * Sets a new password and signs the user out everywhere: a reset usually means the old
 * password may be known to someone else, so existing sessions must not survive it.
 */
export async function resetPassword(inst: Instance, input: z.infer<typeof resetInput>) {
  if (input.password.length < inst.settings.passwordMinLength)
    throw errors.badRequest("password_too_short", `Password must be at least ${inst.settings.passwordMinLength} characters`);
  // Before the code is used up, so picking a breached password doesn't cost the user their code.
  await assertNotBreached(inst, input.password);
  await assertSsoNotRequired(inst.id, input.email);
  const idx = emailIndex(inst.id, input.email);
  if (!(await consumeCode("reset_password", idx, input.code)))
    throw errors.badRequest("invalid_code", "That code is incorrect or has expired");
  const [row] = await db()
    .select({ emailId: schema.emailAddresses.id, userId: schema.emailAddresses.userId })
    .from(schema.emailAddresses)
    .where(and(eq(schema.emailAddresses.instanceId, inst.id), eq(schema.emailAddresses.emailIndex, idx)));
  if (!row) throw errors.badRequest("invalid_code", "That code is incorrect or has expired");

  const hash = await hashPassword(input.password);
  const revoked = await db().transaction(async (tx) => {
    await tx
      .insert(schema.passwords)
      .values({ userId: row.userId, hash })
      .onConflictDoUpdate({ target: schema.passwords.userId, set: { hash, updatedAt: new Date() } });
    // Receiving the code proves control of the inbox.
    await tx.update(schema.emailAddresses).set({ verifiedAt: new Date() }).where(eq(schema.emailAddresses.id, row.emailId));
    return tx
      .update(schema.sessions)
      .set({ status: "revoked" })
      .where(and(eq(schema.sessions.userId, row.userId), eq(schema.sessions.status, "active")))
      .returning({ h: schema.sessions.refreshTokenHash });
  });
  if (revoked.length) await cache().del(...revoked.map((r) => `sess:${r.h}`));
  await unlockUser(inst, row.userId, { type: "user", id: row.userId, reason: "password_reset" });
  void record(inst.id, "user.password_reset", { actor: { type: "user", id: row.userId }, target: row.userId, data: { sessionsRevoked: revoked.length } });
}
