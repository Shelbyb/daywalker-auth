import { and, eq } from "drizzle-orm";
import { z } from "zod";
import { db, schema } from "../db";
import { hashPassword, verifyPassword, dummyHash, encrypt, decrypt, encryptNullable, decryptNullable, blindIndex } from "../crypto";
import { newId } from "../ids";
import { errors } from "../http";
import type { Instance } from "../db/schema";

const email = z.string().trim().toLowerCase().email().max(254);

export const signUpInput = z.object({
  email,
  password: z.string().max(256),
  firstName: z.string().trim().max(100).optional(),
  lastName: z.string().trim().max(100).optional(),
});
/** Scoped per instance so the same email in two apps doesn't produce linkable index values. */
const emailIndex = (instanceId: string, email: string) => blindIndex(email, `email:${instanceId}`);

export const signInInput = z.object({ email, password: z.string().max(256) });

export async function signUp(inst: Instance, input: z.infer<typeof signUpInput>) {
  if (input.password.length < inst.settings.passwordMinLength)
    throw errors.badRequest("password_too_short", `Password must be at least ${inst.settings.passwordMinLength} characters`);

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
    });
  } catch (e) {
    const code = (e as { code?: string; cause?: { code?: string } }).cause?.code ?? (e as { code?: string }).code;
    if (code === "23505") throw errors.conflict("email_taken", "That email address is already in use");
    throw e;
  }
  return userId;
}

export async function signIn(inst: Instance, input: z.infer<typeof signInInput>) {
  const [row] = await db()
    .select({ userId: schema.users.id, banned: schema.users.banned, hash: schema.passwords.hash })
    .from(schema.emailAddresses)
    .innerJoin(schema.users, eq(schema.users.id, schema.emailAddresses.userId))
    .leftJoin(schema.passwords, eq(schema.passwords.userId, schema.users.id))
    .where(and(eq(schema.emailAddresses.instanceId, inst.id), eq(schema.emailAddresses.emailIndex, emailIndex(inst.id, input.email))));

  // Always run a verify so timing doesn't reveal whether the email exists.
  const ok = await verifyPassword(row?.hash ?? (await dummyHash()), input.password);
  if (!row || !row.hash || !ok) throw errors.badRequest("invalid_credentials", "Email or password is incorrect");
  if (row.banned) throw errors.forbidden("This account is suspended");
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
    ...(opts.includePrivate ? { privateMetadata: JSON.parse(decryptNullable(u.privateMetadataEnc, `users.private_metadata:${u.id}`) ?? "{}"), banned: u.banned } : {}),
    lastSignInAt: u.lastSignInAt,
    createdAt: u.createdAt,
  };
}
