import { and, eq } from "drizzle-orm";
import { record, recordForUser } from "../audit";
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
import { env } from "../env";
import { newId, sha256 } from "../ids";
import { errors } from "../http";
import { getUser } from "./users";
import type { Instance } from "../db/schema";

const CHALLENGE_TTL = 300;
const MAX_PASSKEYS = 10;

const b64url = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");
const fromB64url = (s: string) => new Uint8Array(Buffer.from(s, "base64url"));

/**
 * The domain passkeys are bound to. Defaults to this service's hostname. Set PASSKEY_RP_ID
 * to a parent domain (e.g. "example.com") so apps on subdomains can use passkeys directly.
 */
export function rpId() {
  return process.env.PASSKEY_RP_ID || new URL(env().APP_URL).hostname;
}

/** This service, plus allowed app origins that fall under the RP ID. */
export function expectedOrigins(inst: Instance) {
  const id = rpId();
  const own = new URL(env().APP_URL).origin;
  const apps = inst.allowedOrigins.filter((o) => {
    const host = new URL(o).hostname;
    return host === id || host.endsWith(`.${id}`);
  });
  return [own, ...apps];
}

// ---------- Registration (signed in, fresh session) ----------

export async function registrationOptions(inst: Instance, userId: string, sessionId: string) {
  const user = await getUser(inst.id, userId);
  if (!user) throw errors.unauthorized();
  const existing = await db().select().from(schema.passkeys).where(eq(schema.passkeys.userId, userId));
  if (existing.length >= MAX_PASSKEYS) throw errors.badRequest("too_many_passkeys", `You can have up to ${MAX_PASSKEYS} passkeys`);
  const email = user.emailAddresses.find((e) => e.primary)?.email ?? userId;
  const name = [user.firstName, user.lastName].filter(Boolean).join(" ");
  const options = await newRegistrationOptions(inst, userId, email, name, existing);
  await cache().set(`pk:reg:${sessionId}`, options.challenge, "EX", CHALLENGE_TTL);
  return options;
}

/** Options for creating a passkey. Shared by adding one to an account and by passkey-first sign-up. */
export async function newRegistrationOptions(inst: Instance, userId: string, email: string, name: string, existing: { credentialId: string; transports: string[] }[] = []) {
  return generateRegistrationOptions({
    rpName: inst.name,
    rpID: rpId(),
    userName: email,
    userDisplayName: name || email,
    userID: new TextEncoder().encode(userId),
    attestationType: "none", // we don't restrict authenticator makes, so don't collect attestation
    // Never register the same authenticator twice.
    excludeCredentials: existing.map((p) => ({ id: p.credentialId, transports: p.transports as AuthenticatorTransport[] })),
    authenticatorSelection: {
      residentKey: "required", // discoverable: lets people sign in without typing an email
      userVerification: "required", // biometric or device PIN on every use
    },
  });
}

/** Checks the browser's attestation against the challenge we issued. Returns the credential to store. */
export async function checkRegistration(inst: Instance, response: RegistrationResponseJSON, challenge: string) {
  let result;
  try {
    result = await verifyRegistrationResponse({
      response,
      expectedChallenge: challenge,
      expectedOrigin: expectedOrigins(inst),
      expectedRPID: rpId(),
      requireUserVerification: true,
    });
  } catch {
    throw errors.badRequest("passkey_invalid", "That passkey couldn't be verified");
  }
  if (!result.verified) throw errors.badRequest("passkey_invalid", "That passkey couldn't be verified");
  const { credential, credentialDeviceType, credentialBackedUp } = result.registrationInfo;
  return {
    credentialId: credential.id,
    publicKey: b64url(credential.publicKey),
    counter: credential.counter,
    transports: (credential.transports ?? response.response.transports ?? []) as string[],
    deviceType: credentialDeviceType,
    backedUp: credentialBackedUp,
  };
}

export const passkeyName = (label: string | undefined, backedUp: boolean) => (label?.trim() || (backedUp ? "Synced passkey" : "Passkey")).slice(0, 60);

export async function verifyRegistration(inst: Instance, userId: string, sessionId: string, response: RegistrationResponseJSON, label?: string) {
  const challenge = await cache().getdel(`pk:reg:${sessionId}`); // single use
  if (!challenge) throw errors.badRequest("challenge_expired", "Passkey setup timed out. Please try again");
  const c = await checkRegistration(inst, response, challenge);
  const id = newId("pk");
  try {
    await db().insert(schema.passkeys).values({ id, instanceId: inst.id, userId, ...c, name: passkeyName(label, c.backedUp) });
  } catch (e) {
    const code = (e as { cause?: { code?: string } }).cause?.code ?? (e as { code?: string }).code;
    if (code === "23505") throw errors.conflict("passkey_exists", "This passkey is already registered");
    throw e;
  }
  void record(inst.id, "user.passkey_added", { actor: { type: "user", id: userId }, target: userId, data: { passkeyId: id } });
  return id;
}

// ---------- Sign in (usernameless) ----------

export async function authenticationOptions(inst: Instance, forUserId?: string) {
  let allowCredentials: { id: string; transports?: AuthenticatorTransport[] }[] | undefined;
  if (forUserId) {
    // Re-verification of a signed-in user: only their own passkeys are offered.
    const mine = await db().select({ id: schema.passkeys.credentialId, transports: schema.passkeys.transports }).from(schema.passkeys).where(eq(schema.passkeys.userId, forUserId));
    if (!mine.length) throw errors.badRequest("no_passkey", "No passkey is set up");
    allowCredentials = mine.map((k) => ({ id: k.id, transports: k.transports as AuthenticatorTransport[] }));
  }
  const options = await generateAuthenticationOptions({ rpID: rpId(), userVerification: "required", ...(allowCredentials ? { allowCredentials } : {}) });
  // Keyed by the challenge itself, so the browser holds no extra state; single use.
  await cache().set(`pk:auth:${sha256(options.challenge)}`, inst.id, "EX", CHALLENGE_TTL);
  return options;
}

function challengeOf(response: AuthenticationResponseJSON) {
  try {
    const client = JSON.parse(Buffer.from(response.response.clientDataJSON, "base64url").toString("utf8"));
    return typeof client.challenge === "string" ? (client.challenge as string) : null;
  } catch {
    return null;
  }
}

/** Returns the signed-in user's ID. Any failure is the same generic error. */
export async function verifyAuthentication(inst: Instance, response: AuthenticationResponseJSON) {
  const fail = () => errors.badRequest("passkey_invalid", "That passkey couldn't be verified");
  const challenge = challengeOf(response);
  if (!challenge) throw fail();
  const owner = await cache().getdel(`pk:auth:${sha256(challenge)}`);
  if (owner !== inst.id) throw fail(); // unknown, expired, reused, or issued for another instance

  const [pk] = await db()
    .select({ p: schema.passkeys, banned: schema.users.banned })
    .from(schema.passkeys)
    .innerJoin(schema.users, eq(schema.users.id, schema.passkeys.userId))
    .where(and(eq(schema.passkeys.instanceId, inst.id), eq(schema.passkeys.credentialId, response.id)));
  if (!pk) throw fail();

  // If the authenticator reports which user it belongs to, it must match.
  const handle = response.response.userHandle;
  if (handle && Buffer.from(handle, "base64url").toString("utf8") !== pk.p.userId) throw fail();

  let result;
  try {
    result = await verifyAuthenticationResponse({
      response,
      expectedChallenge: challenge,
      expectedOrigin: expectedOrigins(inst),
      expectedRPID: rpId(),
      requireUserVerification: true,
      credential: {
        id: pk.p.credentialId,
        publicKey: fromB64url(pk.p.publicKey),
        counter: pk.p.counter,
        transports: pk.p.transports,
      },
    });
  } catch {
    // Includes a signature counter that went backwards: a sign the authenticator was cloned.
    throw fail();
  }
  if (!result.verified) throw fail();
  if (pk.banned) throw errors.forbidden("This account is suspended");

  await db()
    .update(schema.passkeys)
    .set({ counter: result.authenticationInfo.newCounter, lastUsedAt: new Date() })
    .where(eq(schema.passkeys.id, pk.p.id));
  return pk.p.userId;
}

// ---------- Management (signed in) ----------

export async function listPasskeys(userId: string) {
  const rows = await db().select().from(schema.passkeys).where(eq(schema.passkeys.userId, userId));
  return rows.map((p) => ({ id: p.id, name: p.name, synced: p.backedUp, lastUsedAt: p.lastUsedAt, createdAt: p.createdAt }));
}

export async function renamePasskey(userId: string, id: string, name: string) {
  const rows = await db()
    .update(schema.passkeys)
    .set({ name: name.trim().slice(0, 60) || "Passkey" })
    .where(and(eq(schema.passkeys.id, id), eq(schema.passkeys.userId, userId)))
    .returning({ id: schema.passkeys.id });
  if (!rows.length) throw errors.notFound("Passkey not found");
}

export async function deletePasskey(userId: string, id: string) {
  const rows = await db()
    .delete(schema.passkeys)
    .where(and(eq(schema.passkeys.id, id), eq(schema.passkeys.userId, userId)))
    .returning({ id: schema.passkeys.id });
  if (!rows.length) throw errors.notFound("Passkey not found");
  void recordForUser(userId, "user.passkey_removed", { data: { passkeyId: id } });
}
