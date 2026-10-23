/**
 * Security keys (YubiKey and similar) as a second factor, over WebAuthn.
 *
 * They live in their own table and are only ever accepted at the second-factor step, after the
 * password (or social/email) sign-in. A security key can't sign anyone in by itself, unlike a passkey.
 * Low level only; the rules about when one may be added or removed live in mfa.ts.
 */
import { and, eq } from "drizzle-orm";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
  type RegistrationResponseJSON,
  type AuthenticationResponseJSON,
  type AuthenticatorTransport,
} from "@simplewebauthn/server";
import { db, schema } from "../db";
import { cache } from "../cache";
import { newId } from "../ids";
import { errors } from "../http";
import { getUser } from "./users";
import { expectedOrigins, rpId } from "./passkeys";
import type { Instance } from "../db/schema";

const CHALLENGE_TTL = 300;
export const MAX_SECURITY_KEYS = 5;

const b64url = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");
const fromB64url = (s: string) => new Uint8Array(Buffer.from(s, "base64url"));

export async function countSecurityKeys(userId: string) {
  return (await db().select({ id: schema.mfaSecurityKeys.id }).from(schema.mfaSecurityKeys).where(eq(schema.mfaSecurityKeys.userId, userId))).length;
}

export async function listSecurityKeys(userId: string) {
  const rows = await db().select().from(schema.mfaSecurityKeys).where(eq(schema.mfaSecurityKeys.userId, userId));
  return rows
    .sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime())
    .map((k) => ({ id: k.id, name: k.name, lastUsedAt: k.lastUsedAt, createdAt: k.createdAt }));
}

// ---------- Registration ----------

export async function securityKeyRegistrationOptions(inst: Instance, userId: string, sessionId: string) {
  const user = await getUser(inst.id, userId);
  if (!user) throw errors.unauthorized();
  const existing = await db().select().from(schema.mfaSecurityKeys).where(eq(schema.mfaSecurityKeys.userId, userId));
  if (existing.length >= MAX_SECURITY_KEYS) throw errors.badRequest("too_many_keys", `You can add up to ${MAX_SECURITY_KEYS} security keys`);
  const email = user.emailAddresses.find((e) => e.primary)?.email ?? userId;

  const options = await generateRegistrationOptions({
    rpName: inst.name,
    rpID: rpId(),
    userName: email,
    userDisplayName: [user.firstName, user.lastName].filter(Boolean).join(" ") || email,
    // A different handle than passkeys use, so an authenticator that stores this credential on the
    // key itself can never overwrite one of the person's passkeys.
    userID: new TextEncoder().encode(`sk:${userId}`),
    attestationType: "none",
    excludeCredentials: existing.map((k) => ({ id: k.credentialId, transports: k.transports as AuthenticatorTransport[] })),
    authenticatorSelection: { residentKey: "discouraged", userVerification: "preferred" },
  });
  await cache().set(`sk:reg:${sessionId}`, options.challenge, "EX", CHALLENGE_TTL);
  return options;
}

export async function verifySecurityKeyRegistration(inst: Instance, userId: string, sessionId: string, response: RegistrationResponseJSON, label?: string) {
  const challenge = await cache().getdel(`sk:reg:${sessionId}`); // single use
  if (!challenge) throw errors.badRequest("challenge_expired", "Security key setup timed out. Please try again");
  const invalid = () => errors.badRequest("security_key_invalid", "That security key couldn't be verified");

  let result;
  try {
    result = await verifyRegistrationResponse({ response, expectedChallenge: challenge, expectedOrigin: expectedOrigins(inst), expectedRPID: rpId(), requireUserVerification: false });
  } catch {
    throw invalid();
  }
  if (!result.verified) throw invalid();

  const { credential } = result.registrationInfo;
  const id = newId("sk");
  try {
    await db().insert(schema.mfaSecurityKeys).values({
      id,
      instanceId: inst.id,
      userId,
      credentialId: credential.id,
      publicKey: b64url(credential.publicKey),
      counter: credential.counter,
      transports: credential.transports ?? response.response.transports ?? [],
      name: (label?.trim() || "Security key").slice(0, 60),
    });
  } catch (e) {
    const code = (e as { cause?: { code?: string } }).cause?.code ?? (e as { code?: string }).code;
    if (code === "23505") throw errors.conflict("security_key_exists", "This security key is already registered");
    throw e;
  }
  return id;
}

// ---------- Second-factor sign-in ----------

/** Options for the sign-in prompt: only this person's keys are allowed to answer. */
export async function securityKeyAuthenticationOptions(userId: string) {
  const keys = await db().select().from(schema.mfaSecurityKeys).where(eq(schema.mfaSecurityKeys.userId, userId));
  if (!keys.length) throw errors.badRequest("no_security_key", "No security key is set up");
  const options = await generateAuthenticationOptions({
    rpID: rpId(),
    userVerification: "preferred",
    allowCredentials: keys.map((k) => ({ id: k.credentialId, transports: k.transports as AuthenticatorTransport[] })),
  });
  await cache().set(`sk:auth:${userId}`, options.challenge, "EX", CHALLENGE_TTL);
  return options;
}

/** True only for a fresh, correctly signed answer from one of this user's keys. Never throws for a bad answer. */
export async function verifySecurityKeyAuthentication(inst: Instance, userId: string, response: AuthenticationResponseJSON) {
  const challenge = await cache().getdel(`sk:auth:${userId}`); // single use, whether it succeeds or not
  if (!challenge) return false;
  const [key] = await db()
    .select()
    .from(schema.mfaSecurityKeys)
    .where(and(eq(schema.mfaSecurityKeys.userId, userId), eq(schema.mfaSecurityKeys.credentialId, response.id)));
  if (!key) return false;
  try {
    const r = await verifyAuthenticationResponse({
      response,
      expectedChallenge: challenge,
      expectedOrigin: expectedOrigins(inst),
      expectedRPID: rpId(),
      requireUserVerification: false,
      credential: { id: key.credentialId, publicKey: fromB64url(key.publicKey), counter: key.counter, transports: key.transports as AuthenticatorTransport[] },
    });
    if (!r.verified) return false;
    await db().update(schema.mfaSecurityKeys).set({ counter: r.authenticationInfo.newCounter, lastUsedAt: new Date() }).where(eq(schema.mfaSecurityKeys.id, key.id));
    return true;
  } catch {
    return false; // includes a signature counter that went backwards (a cloned key)
  }
}

// ---------- Management ----------

export async function renameSecurityKey(userId: string, id: string, name: string) {
  const rows = await db()
    .update(schema.mfaSecurityKeys)
    .set({ name: name.trim().slice(0, 60) || "Security key" })
    .where(and(eq(schema.mfaSecurityKeys.id, id), eq(schema.mfaSecurityKeys.userId, userId)))
    .returning({ id: schema.mfaSecurityKeys.id });
  if (!rows.length) throw errors.notFound("Security key not found");
}

export async function deleteSecurityKeyRow(userId: string, id: string) {
  const rows = await db()
    .delete(schema.mfaSecurityKeys)
    .where(and(eq(schema.mfaSecurityKeys.id, id), eq(schema.mfaSecurityKeys.userId, userId)))
    .returning({ id: schema.mfaSecurityKeys.id });
  if (!rows.length) throw errors.notFound("Security key not found");
}
