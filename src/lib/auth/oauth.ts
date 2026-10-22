import { createHash } from "node:crypto";
import { DEFS, exchangeCode, labelFor, type Profile, type ProviderName, type ProviderSettings } from "./oauth-providers";
import { and, eq } from "drizzle-orm";
import { db, schema } from "../db";
import { cache } from "../cache";
import { env } from "../env";
import { blindIndex, decrypt, encrypt, encryptNullable } from "../crypto";
import { newId, newToken, sha256 } from "../ids";
import { errors } from "../http";
import { getInstance } from "./instance";
import type { Instance } from "../db/schema";
import { legalOf, acceptanceRow } from "./legal";

export { PROVIDERS, isProvider, labelFor, type ProviderName, type ProviderSettings } from "./oauth-providers";

export const callbackUrl = (p: ProviderName) => `${env().APP_URL}/v1/oauth/callback/${p}`;
/** Providers that return a signed ID token we verify (and so get a nonce). */
const USES_NONCE: ProviderName[] = ["microsoft", "apple", "oidc"];

// ---------- Provider configuration (backend API) ----------

export async function setProviderConfig(
  instanceId: string,
  provider: ProviderName,
  cfg: { clientId: string; clientSecret: string; enabled: boolean; settings?: ProviderSettings },
) {
  const clientSecretEnc = encrypt(cfg.clientSecret, `oauth_providers.client_secret:${instanceId}:${provider}`);
  await db()
    .insert(schema.oauthProviders)
    .values({ instanceId, provider, clientId: cfg.clientId, clientSecretEnc, enabled: cfg.enabled, settings: cfg.settings ?? {} })
    .onConflictDoUpdate({
      target: [schema.oauthProviders.instanceId, schema.oauthProviders.provider],
      set: { clientId: cfg.clientId, clientSecretEnc, enabled: cfg.enabled, settings: cfg.settings ?? {}, updatedAt: new Date() },
    });
  await cache().del(`oauth:enabled:${instanceId}`);
}

/** Enabled providers with their button labels (a custom OIDC provider has its own name). */
export async function enabledProviders(instanceId: string): Promise<{ id: ProviderName; label: string }[]> {
  const hit = await cache().get(`oauth:enabled:${instanceId}`);
  if (hit) return JSON.parse(hit);
  const rows = await db()
    .select({ provider: schema.oauthProviders.provider, settings: schema.oauthProviders.settings })
    .from(schema.oauthProviders)
    .where(and(eq(schema.oauthProviders.instanceId, instanceId), eq(schema.oauthProviders.enabled, true)));
  const list = rows.map((r) => ({ id: r.provider, label: labelFor(r.provider, r.settings) }));
  await cache().set(`oauth:enabled:${instanceId}`, JSON.stringify(list), "EX", 300);
  return list;
}

async function providerConfig(instanceId: string, provider: ProviderName) {
  const [row] = await db()
    .select()
    .from(schema.oauthProviders)
    .where(and(eq(schema.oauthProviders.instanceId, instanceId), eq(schema.oauthProviders.provider, provider), eq(schema.oauthProviders.enabled, true)));
  if (!row) throw errors.badRequest("provider_disabled", `Sign-in with ${provider} isn't enabled for this app`);
  return { clientId: row.clientId, clientSecret: decrypt(row.clientSecretEnc, `oauth_providers.client_secret:${instanceId}:${provider}`), settings: row.settings ?? {} };
}

// ---------- Flow ----------

type PendingState = { instanceId: string; provider: ProviderName; verifier: string; nonce: string; redirect: string | null; legalAccepted?: boolean };
const STATE_TTL = 600;
export const STATE_COOKIE = "__dw_oauth";

/**
 * Step 1. Returns the provider URL and a state value that must also be set as an
 * HttpOnly cookie: the callback requires both to match, so an attacker can't complete
 * a flow they started in someone else's browser (login CSRF).
 */
export async function startOAuth(inst: Instance, provider: ProviderName, redirect: string | null, legalAccepted = false) {
  const cfg = await providerConfig(inst.id, provider);
  const def = DEFS[provider];
  const state = newToken(32);
  const verifier = newToken(48); // PKCE: proves the token request comes from whoever started the flow
  const nonce = newToken(24); // binds the signed ID token to this request
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  const pending: PendingState = { instanceId: inst.id, provider, verifier, nonce, redirect, legalAccepted };
  await cache().set(`oauth:state:${sha256(state)}`, encrypt(JSON.stringify(pending), "oauth_state"), "EX", STATE_TTL);

  const e = await def.endpoints(cfg);
  if (!e.authorize.startsWith("https://") && !testOrInsecure()) throw errors.badRequest("provider_disabled", "This provider is misconfigured");
  const url = new URL(e.authorize);
  url.search = new URLSearchParams({
    client_id: cfg.clientId,
    redirect_uri: callbackUrl(provider),
    response_type: "code",
    scope: e.scope,
    state,
    // Apple doesn't support PKCE; its flow is bound by state, nonce and the signed ID token.
    ...(provider === "apple" ? {} : { code_challenge: challenge, code_challenge_method: "S256" }),
    ...(USES_NONCE.includes(provider) ? { nonce } : {}),
    ...(e.extra ?? {}),
  }).toString();
  return { url: url.toString(), state, maxAge: STATE_TTL, formPost: def.formPost === true };
}

const testOrInsecure = () => process.env.ALLOW_INSECURE_TRANSPORT === "1";

/** Loads and deletes the pending state (single use). Null if missing, expired or not bound to this browser. */
export async function takeState(provider: ProviderName, state: string | null, cookieState: string | undefined) {
  if (!state || !cookieState || state.length > 200 || state !== cookieState) return null;
  const key = `oauth:state:${sha256(state)}`;
  const raw = await cache().getdel(key);
  if (!raw) return null;
  const pending = JSON.parse(decrypt(raw, "oauth_state")) as PendingState;
  if (pending.provider !== provider) return null;
  const inst = await getInstance(pending.instanceId);
  return inst ? { ...pending, inst } : null;
}

/** Step 2. Exchange the code, verify who the user is, find-or-create the user. Returns the user ID. */
export async function completeOAuth(
  inst: Instance,
  provider: ProviderName,
  code: string,
  pending: { verifier: string; nonce: string; legalAccepted?: boolean },
  appleUser: string | null = null,
) {
  const cfg = await providerConfig(inst.id, provider);
  const def = DEFS[provider];
  const e = await def.endpoints(cfg);
  const tok = await exchangeCode(e.token, {
    grant_type: "authorization_code",
    code,
    redirect_uri: callbackUrl(provider),
    client_id: cfg.clientId,
    client_secret: def.secret ? await def.secret(cfg) : cfg.clientSecret,
    ...(provider === "apple" ? {} : { code_verifier: pending.verifier }),
  });
  if (!tok.access_token && !tok.id_token) throw errors.badRequest("oauth_failed", "The provider didn't return a token");
  const profile = await def.profile(cfg, tok, { nonce: pending.nonce, appleUser });
  return linkOrCreate(inst, provider, profile, pending.legalAccepted === true);
}

/**
 * Account matching rules:
 * 1. Known provider identity → that user.
 * 2. Provider gives a *verified* email that matches an existing account → link to it.
 *    If that account's email was never verified, someone may have pre-registered the
 *    address to hijack it later, so its password is removed and its sessions revoked.
 * 3. Otherwise create a new user (provider email must be verified to be attached).
 */
async function linkOrCreate(inst: Instance, provider: ProviderName, p: Profile, legalAccepted: boolean): Promise<string> {
  const identity = blindIndex(p.id, `oauth:${inst.id}:${provider}`);
  const [existing] = await db()
    .select({ userId: schema.oauthAccounts.userId, banned: schema.users.banned })
    .from(schema.oauthAccounts)
    .innerJoin(schema.users, eq(schema.users.id, schema.oauthAccounts.userId))
    .where(and(eq(schema.oauthAccounts.instanceId, inst.id), eq(schema.oauthAccounts.provider, provider), eq(schema.oauthAccounts.providerUserIndex, identity)));
  if (existing) {
    if (existing.banned) throw errors.forbidden("This account is suspended");
    return existing.userId;
  }
  if (!p.email || !p.emailVerified)
    throw errors.badRequest("email_unverified", `Your ${labelFor(provider)} account has no verified email address`);

  const emailIndex = blindIndex(p.email, `email:${inst.id}`);
  const revokedHashes: string[] = [];
  const userId = await db().transaction(async (tx) => {
    const [match] = await tx
      .select({ id: schema.emailAddresses.id, userId: schema.emailAddresses.userId, verifiedAt: schema.emailAddresses.verifiedAt, banned: schema.users.banned })
      .from(schema.emailAddresses)
      .innerJoin(schema.users, eq(schema.users.id, schema.emailAddresses.userId))
      .where(and(eq(schema.emailAddresses.instanceId, inst.id), eq(schema.emailAddresses.emailIndex, emailIndex)));

    let uid: string;
    if (match) {
      if (match.banned) throw errors.forbidden("This account is suspended");
      uid = match.userId;
      if (!match.verifiedAt) {
        await tx.delete(schema.passwords).where(eq(schema.passwords.userId, uid));
        const rows = await tx
          .update(schema.sessions)
          .set({ status: "revoked" })
          .where(and(eq(schema.sessions.userId, uid), eq(schema.sessions.status, "active")))
          .returning({ h: schema.sessions.refreshTokenHash });
        revokedHashes.push(...rows.map((r) => r.h));
        await tx.update(schema.emailAddresses).set({ verifiedAt: new Date() }).where(eq(schema.emailAddresses.id, match.id));
      }
    } else {
      // Only *new* accounts need to accept; existing users signing in with a provider don't.
      if (legalOf(inst).required && !legalAccepted)
        throw errors.badRequest("legal_required", "Please accept the terms to create an account");
      uid = newId("user");
      await tx.insert(schema.users).values({
        id: uid,
        instanceId: inst.id,
        firstNameEnc: encryptNullable(p.firstName, `users.first_name:${uid}`),
        lastNameEnc: encryptNullable(p.lastName, `users.last_name:${uid}`),
        imageUrl: p.imageUrl,
      });
      const emailId = newId("email");
      await tx.insert(schema.emailAddresses).values({
        id: emailId,
        instanceId: inst.id,
        userId: uid,
        emailEnc: encrypt(p.email!, `email_addresses.email:${emailId}`),
        emailIndex,
        isPrimary: true,
        verifiedAt: new Date(),
      });
      if (legalAccepted) await tx.insert(schema.legalAcceptances).values(acceptanceRow(inst, uid, provider));
    }
    const oaId = newId("oa");
    await tx.insert(schema.oauthAccounts).values({
      id: oaId,
      instanceId: inst.id,
      userId: uid,
      provider,
      providerUserIndex: identity,
      emailEnc: encrypt(p.email!, `oauth_accounts.email:${oaId}`),
    });
    return uid;
  });
  if (revokedHashes.length) await cache().del(...revokedHashes.map((h) => `sess:${h}`));
  return userId;
}
