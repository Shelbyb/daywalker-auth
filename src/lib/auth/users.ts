import { and, eq } from "drizzle-orm";
import { assertEmailAllowed } from "./signup-protection";
import { assertNotBreached } from "./breach";
import { record } from "../audit";
import { assertSsoNotRequired } from "./sso-policy";
import { z } from "zod";
import { db, schema } from "../db";
import { hashPassword, verifyPassword, dummyHash, encrypt, decrypt, encryptNullable, decryptNullable, blindIndex } from "../crypto";
import { newId } from "../ids";
import { errors } from "../http";
import type { Instance } from "../db/schema";
import { hasTwoFactor } from "./mfa";
import { legalOf, acceptanceRow } from "./legal";
import { emit } from "../webhooks";
import { cache } from "../cache";
import * as lockout from "./lockout";
import { lockStatus } from "./lockout";

const email = z.string().trim().toLowerCase().email().max(254);

export const signUpInput = z.object({
  email,
  password: z.string().max(256),
  firstName: z.string().trim().max(100).optional(),
  lastName: z.string().trim().max(100).optional(),
  legalAccepted: z.boolean().optional(),
  /** Turnstile answer, when the instance turned the human check on. */
  captchaToken: z.string().max(2048).optional(),
});
/** Scoped per instance so the same email in two apps doesn't produce linkable index values. */
const emailIndex = (instanceId: string, email: string) => blindIndex(email, `email:${instanceId}`);

export const signInInput = z.object({ email, password: z.string().max(256), captchaToken: z.string().max(2048).optional() });

export async function signUp(inst: Instance, input: z.infer<typeof signUpInput>) {
  await assertSsoNotRequired(inst.id, input.email);
  assertEmailAllowed(inst, input.email);
  if (input.password.length < inst.settings.passwordMinLength)
    throw errors.badRequest("password_too_short", `Password must be at least ${inst.settings.passwordMinLength} characters`);

  // Checked before hashing, so a missing tick fails fast.
  if (legalOf(inst).required && input.legalAccepted !== true)
    throw errors.badRequest("legal_required", "Please accept the terms to create an account");
  await assertNotBreached(inst, input.password);
  const hash = await hashPassword(input.password);
  const userId = newId("user");
  try {
    await db().transaction(async (tx) => {
      await tx.insert(schema.users).values({
        id: userId,
        instanceId: inst.id,
        firstNameEnc: encryptNullable(input.firstName, `users.first_name:${userId}`),
        lastNameEnc: encryptNullable(input.lastName, `users.last_name:${userId}`),
      });
      // The unique (instance_id, email) index is the real guard against races.
      const emailId = newId("email");
      await tx.insert(schema.emailAddresses).values({
        id: emailId,
        instanceId: inst.id,
        userId,
        emailEnc: encrypt(input.email, `email_addresses.email:${emailId}`),
        emailIndex: emailIndex(inst.id, input.email),
        isPrimary: true,
      });
      await tx.insert(schema.passwords).values({ userId, hash });
      if (input.legalAccepted) await tx.insert(schema.legalAcceptances).values(acceptanceRow(inst, userId, "password"));
    });
  } catch (e) {
    const code = (e as { code?: string; cause?: { code?: string } }).cause?.code ?? (e as { code?: string }).code;
    if (code === "23505") throw errors.conflict("email_taken", "That email address is already in use");
    throw e;
  }
  void emit(inst.id, "user.created", { userId, email: input.email });
  void record(inst.id, "user.signed_up", { actor: { type: "user", id: userId }, target: userId, data: { method: "password" } });
  return userId;
}

export async function signIn(inst: Instance, input: z.infer<typeof signInInput>) {
  await assertSsoNotRequired(inst.id, input.email);
  const [row] = await db()
    .select({ userId: schema.users.id, banned: schema.users.banned, hash: schema.passwords.hash })
    .from(schema.emailAddresses)
    .innerJoin(schema.users, eq(schema.users.id, schema.emailAddresses.userId))
    .leftJoin(schema.passwords, eq(schema.passwords.userId, schema.users.id))
    .where(and(eq(schema.emailAddresses.instanceId, inst.id), eq(schema.emailAddresses.emailIndex, emailIndex(inst.id, input.email))));

  // Unknown emails get the same counters and lock (keyed by the email's blind index), so nothing reveals whether the account exists.
  const subject = row ? { userId: row.userId } : { emailIndex: emailIndex(inst.id, input.email) };
  const slot = await lockout.reserve(inst, subject, "pw");
  // Always run a verify so timing doesn't reveal whether the email exists.
  const ok = await verifyPassword(row?.hash ?? (await dummyHash()), input.password);
  if (!row || !row.hash || !ok) {
    await lockout.failed(inst, subject, slot, "password");
    // Only failures against a real account are logged; unknown emails would just fill the log.
    if (row) void record(inst.id, "user.sign_in_failed", { target: row.userId, data: { reason: "wrong_password" } });
    throw errors.badRequest("invalid_credentials", "Email or password is incorrect");
  }
  await lockout.succeeded(inst, subject, "pw");
  if (row.banned) {
    void record(inst.id, "user.sign_in_blocked", { target: row.userId, data: { reason: "suspended" } });
    throw errors.forbidden("This account is suspended");
  }
  return row.userId;
}

/** Public shape returned by both APIs. Never includes private metadata or password data. */
export async function getUser(instanceId: string, userId: string, opts: { includePrivate?: boolean } = {}) {
  const u = await db().query.users.findFirst({
    where: and(eq(schema.users.id, userId), eq(schema.users.instanceId, instanceId)),
  });
  if (!u) return null;
  const emails = await db()
    .select({ id: schema.emailAddresses.id, emailEnc: schema.emailAddresses.emailEnc, isPrimary: schema.emailAddresses.isPrimary, verified: schema.emailAddresses.verifiedAt })
    .from(schema.emailAddresses)
    .where(eq(schema.emailAddresses.userId, userId));
  return {
    id: u.id,
    firstName: decryptNullable(u.firstNameEnc, `users.first_name:${u.id}`),
    lastName: decryptNullable(u.lastNameEnc, `users.last_name:${u.id}`),
    imageUrl: u.imageUrl,
    emailAddresses: emails.map((e) => ({ id: e.id, email: decrypt(e.emailEnc, `email_addresses.email:${e.id}`), primary: e.isPrimary, verified: !!e.verified })),
    publicMetadata: u.publicMetadata,
    twoFactorEnabled: await hasTwoFactor(u.id),
    ...(opts.includePrivate ? { lockedUntil: await lockStatus(instanceId, u.id), deletionScheduledAt: u.deletionScheduledAt?.toISOString() ?? null, privateMetadata: JSON.parse(decryptNullable(u.privateMetadataEnc, `users.private_metadata:${u.id}`) ?? "{}"), banned: u.banned } : {}),
    lastSignInAt: u.lastSignInAt,
    createdAt: u.createdAt,
  };
}

const purgeSessions = async (instanceId: string, userId: string) => {
  const sess = await db()
    .select({ h: schema.sessions.refreshTokenHash })
    .from(schema.sessions)
    .where(and(eq(schema.sessions.userId, userId), eq(schema.sessions.instanceId, instanceId)));
  if (sess.length) await cache().del(...sess.map((x) => `sess:${x.h}`));
};

/** Deletes a user (cascades to emails, password, sessions) and drops their cached sessions. */
export async function deleteUser(instanceId: string, userId: string) {
  const sess = await db()
    .select({ h: schema.sessions.refreshTokenHash })
    .from(schema.sessions)
    .where(and(eq(schema.sessions.userId, userId), eq(schema.sessions.instanceId, instanceId)));
  const [deleted] = await db()
    .delete(schema.users)
    .where(and(eq(schema.users.id, userId), eq(schema.users.instanceId, instanceId)))
    .returning({ id: schema.users.id });
  if (!deleted) throw errors.notFound("User not found");
  if (sess.length) await cache().del(...sess.map((x) => `sess:${x.h}`));
  void emit(instanceId, "user.deleted", { userId });
}

/** Suspend or restore a user. Suspending takes effect on their next token refresh. */
export async function setBanned(instanceId: string, userId: string, banned: boolean) {
  const rows = await db()
    .update(schema.users)
    .set({ banned })
    .where(and(eq(schema.users.id, userId), eq(schema.users.instanceId, instanceId)))
    .returning({ id: schema.users.id });
  if (!rows.length) throw errors.notFound("User not found");
  await purgeSessions(instanceId, userId);
}
