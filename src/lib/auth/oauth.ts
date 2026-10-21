import { createHash } from "node:crypto";
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

export type ProviderName = "google" | "github";
export const PROVIDERS: ProviderName[] = ["google", "github"];
export const isProvider = (p: string): p is ProviderName => (PROVIDERS as string[]).includes(p);

type Profile = {
  id: string;
  email: string | null;
  emailVerified: boolean;
  firstName: string | null;
  lastName: string | null;
  imageUrl: string | null;
};

type Endpoints = { authorize: string; token: string; scope: string };

/**
 * Tests can point providers at a local mock, but only on a plain-HTTP dev deployment,
 * so a misconfigured production server can never be redirected to a fake provider.
 */
function testBase() {
  const base = process.env.OAUTH_TEST_BASE_URL;
  if (!base) return null;
  if (env().APP_URL.startsWith("https://")) throw new Error("OAUTH_TEST_BASE_URL is not allowed on an HTTPS deployment");
  return base.replace(/\/$/, "");
}

function endpoints(p: ProviderName): Endpoints & { api: string } {
  const t = testBase();
  if (t) return { authorize: `${t}/${p}/authorize`, token: `${t}/${p}/token`, api: `${t}/${p}/api`, scope: p === "google" ? "openid email profile" : "read:user user:email" };
  return p === "google"
    ? { authorize: "https://accounts.google.com/o/oauth2/v2/auth", token: "https://oauth2.googleapis.com/token", api: "https://openidconnect.googleapis.com", scope: "openid email profile" }
    : { authorize: "https://github.com/login/oauth/authorize", token: "https://github.com/login/oauth/access_token", api: "https://api.github.com", scope: "read:user user:email" };
}

export const callbackUrl = (p: ProviderName) => `${env().APP_URL}/v1/oauth/callback/${p}`;

async function json<T>(res: Response, what: string): Promise<T> {
  if (!res.ok) throw new Error(`${what} failed: ${res.status}`);
  return (await res.json()) as T;
}

async function fetchProfile(p: ProviderName, accessToken: string): Promise<Profile> {
  const { api } = endpoints(p);
  const headers = { authorization: `Bearer ${accessToken}`, accept: "application/json", "user-agent": "daywalker-auth" };
  if (p === "google") {
    const u = await json<{ sub: string; email?: string; email_verified?: boolean; given_name?: string; family_name?: string; picture?: string }>(
      await fetch(`${api}/v1/userinfo`, { headers }),
      "Google userinfo",
    );
    return { id: u.sub, email: u.email?.toLowerCase() ?? null, emailVerified: u.email_verified === true, firstName: u.given_name ?? null, lastName: u.family_name ?? null, imageUrl: u.picture ?? null };
  }
  const u = await json<{ id: number; name?: string | null; avatar_url?: string }>(await fetch(`${api}/user`, { headers }), "GitHub user");
  // The profile email may be unset or unverified; only trust the verified primary from /user/emails.
  const emails = await json<{ email: string; primary: boolean; verified: boolean }[]>(await fetch(`${api}/user/emails`, { headers }), "GitHub emails");
  const primary = emails.find((e) => e.primary && e.verified);
  const [first, ...rest] = (u.name ?? "").trim().split(/\s+/).filter(Boolean);
  return { id: String(u.id), email: primary?.email.toLowerCase() ?? null, emailVerified: !!primary, firstName: first ?? null, lastName: rest.join(" ") || null, imageUrl: u.avatar_url ?? null };
}

// ---------- Provider configuration (backend API) ----------

export async function setProviderConfig(instanceId: string, provider: ProviderName, cfg: { clientId: string; clientSecret: string; enabled: boolean }) {
  const clientSecretEnc = encrypt(cfg.clientSecret, `oauth_providers.client_secret:${instanceId}:${provider}`);
  await db()
    .insert(schema.oauthProviders)
    .values({ instanceId, provider, clientId: cfg.clientId, clientSecretEnc, enabled: cfg.enabled })
    .onConflictDoUpdate({
      target: [schema.oauthProviders.instanceId, schema.oauthProviders.provider],
      set: { clientId: cfg.clientId, clientSecretEnc, enabled: cfg.enabled, updatedAt: new Date() },
    });
  await cache().del(`oauth:enabled:${instanceId}`);
}

export async function enabledProviders(instanceId: string): Promise<ProviderName[]> {
  const hit = await cache().get(`oauth:enabled:${instanceId}`);
  if (hit) return JSON.parse(hit);
  const rows = await db()
    .select({ provider: schema.oauthProviders.provider })
    .from(schema.oauthProviders)
    .where(and(eq(schema.oauthProviders.instanceId, instanceId), eq(schema.oauthProviders.enabled, true)));
  const list = rows.map((r) => r.provider);
  await cache().set(`oauth:enabled:${instanceId}`, JSON.stringify(list), "EX", 300);
  return list;
}

async function providerConfig(instanceId: string, provider: ProviderName) {
  const [row] = await db()
    .select()
    .from(schema.oauthProviders)
    .where(and(eq(schema.oauthProviders.instanceId, instanceId), eq(schema.oauthProviders.provider, provider), eq(schema.oauthProviders.enabled, true)));
  if (!row) throw errors.badRequest("provider_disabled", `Sign-in with ${provider} isn't enabled for this app`);
  return { clientId: row.clientId, clientSecret: decrypt(row.clientSecretEnc, `oauth_providers.client_secret:${instanceId}:${provider}`) };
}

// ---------- Flow ----------

type PendingState = { instanceId: string; provider: ProviderName; verifier: string; redirect: string | null; legalAccepted?: boolean };
const STATE_TTL = 600;
export const STATE_COOKIE = "__dw_oauth";

/**
 * Step 1. Returns the provider URL and a state value that must also be set as an
 * HttpOnly cookie: the callback requires both to match, so an attacker can't complete
 * a flow they started in someone else's browser (login CSRF).
 */
export async function startOAuth(inst: Instance, provider: ProviderName, redirect: string | null, legalAccepted = false) {
  const { clientId } = await providerConfig(inst.id, provider);
  const state = newToken(32);
  const verifier = newToken(48); // PKCE: proves the token request comes from whoever started the flow
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  const pending: PendingState = { instanceId: inst.id, provider, verifier, redirect, legalAccepted };
  await cache().set(`oauth:state:${sha256(state)}`, encrypt(JSON.stringify(pending), "oauth_state"), "EX", STATE_TTL);

  const e = endpoints(provider);
  const url = new URL(e.authorize);
  url.search = new URLSearchParams({
    client_id: clientId,
    redirect_uri: callbackUrl(provider),
    response_type: "code",
    scope: e.scope,
    state,
    code_challenge: challenge,
    code_challenge_method: "S256",
    ...(provider === "google" ? { prompt: "select_account" } : { allow_signup: "true" }),
  }).toString();
  return { url: url.toString(), state, maxAge: STATE_TTL };
}

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

/** Step 2. Exchange the code, fetch the profile, find-or-create the user. Returns the user ID. */
export async function completeOAuth(inst: Instance, provider: ProviderName, code: string, verifier: string, legalAccepted = false) {
  const { clientId, clientSecret } = await providerConfig(inst.id, provider);
  const tokenRes = await fetch(endpoints(provider).token, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: callbackUrl(provider),
      client_id: clientId,
      client_secret: clientSecret,
      code_verifier: verifier,
    }),
  });
  const tok = await json<{ access_token?: string; error?: string }>(tokenRes, "Token exchange");
  if (!tok.access_token) throw errors.badRequest("oauth_failed", "The provider didn't return an access token");
  const profile = await fetchProfile(provider, tok.access_token);
  return linkOrCreate(inst, provider, profile, legalAccepted);
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
    throw errors.badRequest("email_unverified", `Your ${provider} account has no verified email address`);

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
