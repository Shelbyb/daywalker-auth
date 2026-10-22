/**
 * Social sign-in providers. Each one knows its endpoints, how to prove who the user is, and
 * how far to trust the email address it reports. Every outbound call goes through the SSRF
 * guard (public addresses only, no redirects, size and time limits).
 *
 * Trust rules, per provider:
 * - Google, GitLab, generic OIDC: `email_verified` must be true.
 * - GitHub: only the primary email marked verified by /user/emails.
 * - Discord: `verified` must be true.
 * - Apple: `email_verified` in the signed ID token.
 * - Microsoft: work and school accounts let tenant admins set any email, so it's only trusted
 *   for personal Microsoft accounts or when the token carries `xms_edov: true` (a verified
 *   domain owner). Otherwise the user can still sign in to an account they already linked.
 */
import { createLocalJWKSet, importPKCS8, jwtVerify, SignJWT, type JWTPayload } from "jose";
import { z } from "zod";
import { env } from "../env";
import { errors } from "../http";
import { guardedFetch } from "../net-guard";

export const PROVIDERS = ["google", "github", "microsoft", "apple", "discord", "gitlab", "oidc"] as const;
export type ProviderName = (typeof PROVIDERS)[number];
export const isProvider = (p: string): p is ProviderName => (PROVIDERS as readonly string[]).includes(p);

export type ProviderSettings = {
  /** oidc: required issuer URL. gitlab: optional self-hosted base URL. */
  issuer?: string;
  /** microsoft: tenant ID or "common" | "organizations" | "consumers". */
  tenant?: string;
  /** apple: Team ID and Key ID from the Apple developer account. */
  teamId?: string;
  keyId?: string;
  /** oidc: button label, e.g. "Okta". */
  displayName?: string;
};

export type Profile = { id: string; email: string | null; emailVerified: boolean; firstName: string | null; lastName: string | null; imageUrl: string | null };
export type Cfg = { clientId: string; clientSecret: string; settings: ProviderSettings };
type Tokens = { access_token?: string; id_token?: string };
type Ctx = { nonce: string; appleUser?: string | null };
type Endpoints = { authorize: string; token: string; scope: string; extra?: Record<string, string> };

export const LABELS: Record<ProviderName, string> = {
  google: "Google",
  github: "GitHub",
  microsoft: "Microsoft",
  apple: "Apple",
  discord: "Discord",
  gitlab: "GitLab",
  oidc: "OpenID Connect",
};
export const labelFor = (p: ProviderName, s?: ProviderSettings) => (p === "oidc" && s?.displayName ? s.displayName : LABELS[p]);

const MS_CONSUMER_TENANT = "9188040d-6c67-4c5b-b112-36a304b66dad";

// ---------- Settings validation (dashboard and API) ----------

const httpsUrl = z
  .string()
  .trim()
  .max(500)
  .url("Enter a full URL")
  .refine((u) => u.startsWith("https://") || process.env.ALLOW_INSECURE_TRANSPORT === "1", "Must use https")
  .transform((u) => u.replace(/\/+$/, ""));

export function parseSettings(p: ProviderName, raw: unknown, clientSecret?: string): ProviderSettings {
  const r = (raw ?? {}) as Record<string, unknown>;
  const blank = (v: unknown) => (typeof v === "string" && v.trim() === "" ? undefined : v);
  switch (p) {
    case "oidc":
      return z
        .object({ issuer: httpsUrl, displayName: z.string().trim().min(1).max(40).optional() })
        .parse({ issuer: r.issuer, displayName: blank(r.displayName) });
    case "gitlab":
      return z.object({ issuer: httpsUrl.optional() }).parse({ issuer: blank(r.issuer) });
    case "microsoft":
      return z
        .object({ tenant: z.string().trim().regex(/^[A-Za-z0-9.-]{1,100}$/, "Tenant must be a tenant ID, a domain, or common / organizations / consumers").optional() })
        .parse({ tenant: blank(r.tenant) });
    case "apple": {
      const s = z
        .object({
          teamId: z.string().trim().regex(/^[A-Z0-9]{10}$/, "Team ID is 10 letters and digits"),
          keyId: z.string().trim().regex(/^[A-Z0-9]{10}$/, "Key ID is 10 letters and digits"),
        })
        .parse({ teamId: r.teamId, keyId: r.keyId });
      if (clientSecret !== undefined && !/-----BEGIN PRIVATE KEY-----[\s\S]+-----END PRIVATE KEY-----/.test(clientSecret))
        throw errors.badRequest("invalid_key", "For Apple, paste the whole .p8 private key file as the client secret");
      return s;
    }
    default:
      return {};
  }
}

// ---------- Test mode ----------

/** Tests point providers at a local mock, but only on a plain-HTTP dev deployment. */
export function testBase() {
  const base = process.env.OAUTH_TEST_BASE_URL;
  if (!base) return null;
  if (env().APP_URL.startsWith("https://")) throw new Error("OAUTH_TEST_BASE_URL is not allowed on an HTTPS deployment");
  return base.replace(/\/$/, "");
}

// ---------- HTTP helpers ----------

async function getJson<T>(url: string, headers: Record<string, string>, what: string): Promise<T> {
  const r = await guardedFetch(url, { headers: { accept: "application/json", "user-agent": "daywalker-auth", ...headers } });
  if (r.status < 200 || r.status >= 300) throw new Error(`${what} failed: ${r.status}`);
  return JSON.parse(r.text) as T;
}

export async function exchangeCode(tokenUrl: string, form: Record<string, string>): Promise<Tokens> {
  const r = await guardedFetch(tokenUrl, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json", "user-agent": "daywalker-auth" },
    body: new URLSearchParams(form).toString(),
  });
  if (r.status < 200 || r.status >= 300) throw new Error(`Token exchange failed: ${r.status}`);
  return JSON.parse(r.text) as Tokens;
}

const jwksCache = new Map<string, { at: number; set: ReturnType<typeof createLocalJWKSet> }>();
async function jwks(url: string) {
  const hit = jwksCache.get(url);
  if (hit && Date.now() - hit.at < 10 * 60_000) return hit.set;
  const set = createLocalJWKSet(await getJson(url, {}, "Key set"));
  jwksCache.set(url, { at: Date.now(), set });
  return set;
}

/** Signature, audience, expiry and nonce, then the issuer (exact, or checked by the caller). */
async function verifyIdToken(idToken: string | undefined, jwksUrl: string, audience: string, nonce: string, issuer?: string) {
  if (!idToken) throw errors.badRequest("oauth_failed", "The provider didn't return an ID token");
  const { payload } = await jwtVerify(idToken, await jwks(jwksUrl), { audience, ...(issuer ? { issuer } : {}), clockTolerance: 60 });
  if (payload.nonce !== nonce) throw errors.badRequest("oauth_failed", "The sign-in response didn't match this request");
  return payload as JWTPayload & Record<string, unknown>;
}

const str = (v: unknown) => (typeof v === "string" && v.trim() ? v.trim().slice(0, 200) : null);
const splitName = (name: unknown) => {
  const [first, ...rest] = (str(name) ?? "").split(/\s+/).filter(Boolean);
  return { firstName: first ?? null, lastName: rest.join(" ") || null };
};
const truthy = (v: unknown) => v === true || v === "true";

// ---------- Generic OIDC discovery ----------

type Discovery = { issuer: string; authorization_endpoint: string; token_endpoint: string; userinfo_endpoint?: string; jwks_uri: string };
const discoCache = new Map<string, { at: number; doc: Discovery }>();
async function discover(issuer: string): Promise<Discovery> {
  const hit = discoCache.get(issuer);
  if (hit && Date.now() - hit.at < 60 * 60_000) return hit.doc;
  const doc = await getJson<Discovery>(`${issuer}/.well-known/openid-configuration`, {}, "OpenID discovery");
  // Pin the issuer: a discovery document can't claim to be someone else.
  if (doc.issuer?.replace(/\/+$/, "") !== issuer) throw errors.badRequest("oauth_failed", "The provider's issuer doesn't match the configured issuer");
  for (const k of ["authorization_endpoint", "token_endpoint", "jwks_uri"] as const)
    if (typeof doc[k] !== "string" || !(doc[k].startsWith("https://") || process.env.ALLOW_INSECURE_TRANSPORT === "1"))
      throw errors.badRequest("oauth_failed", "The provider's configuration is incomplete");
  discoCache.set(issuer, { at: Date.now(), doc });
  return doc;
}

// ---------- Apple client secret ----------

/** Apple wants a short-lived ES256 JWT, signed with the developer's .p8 key, as the client secret. */
async function appleClientSecret(cfg: Cfg) {
  const key = await importPKCS8(cfg.clientSecret, "ES256");
  return new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: cfg.settings.keyId })
    .setIssuer(cfg.settings.teamId!)
    .setSubject(cfg.clientId)
    .setAudience("https://appleid.apple.com")
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(key);
}

// ---------- Definitions ----------

type Def = {
  endpoints(cfg: Cfg): Promise<Endpoints>;
  /** The secret sent to the token endpoint (Apple builds one). */
  secret?(cfg: Cfg): Promise<string>;
  profile(cfg: Cfg, tok: Tokens, ctx: Ctx): Promise<Profile>;
  /** Apple posts the callback; the others redirect with a query string. */
  formPost?: boolean;
};

const t = (p: string) => {
  const b = testBase();
  return b ? `${b}/${p}` : null;
};

export const DEFS: Record<ProviderName, Def> = {
  google: {
    async endpoints() {
      const b = t("google");
      return {
        authorize: b ? `${b}/authorize` : "https://accounts.google.com/o/oauth2/v2/auth",
        token: b ? `${b}/token` : "https://oauth2.googleapis.com/token",
        scope: "openid email profile",
        extra: { prompt: "select_account" },
      };
    },
    async profile(_cfg, tok) {
      const api = t("google") ? `${t("google")}/api` : "https://openidconnect.googleapis.com";
      const u = await getJson<Record<string, unknown>>(`${api}/v1/userinfo`, { authorization: `Bearer ${tok.access_token}` }, "Google userinfo");
      return { id: String(u.sub), email: str(u.email)?.toLowerCase() ?? null, emailVerified: u.email_verified === true, firstName: str(u.given_name), lastName: str(u.family_name), imageUrl: str(u.picture) };
    },
  },

  github: {
    async endpoints() {
      const b = t("github");
      return { authorize: b ? `${b}/authorize` : "https://github.com/login/oauth/authorize", token: b ? `${b}/token` : "https://github.com/login/oauth/access_token", scope: "read:user user:email", extra: { allow_signup: "true" } };
    },
    async profile(_cfg, tok) {
      const api = t("github") ? `${t("github")}/api` : "https://api.github.com";
      const h = { authorization: `Bearer ${tok.access_token}` };
      const u = await getJson<{ id: number; name?: string | null; avatar_url?: string }>(`${api}/user`, h, "GitHub user");
      // The profile email may be unset or unverified; only trust the verified primary from /user/emails.
      const emails = await getJson<{ email: string; primary: boolean; verified: boolean }[]>(`${api}/user/emails`, h, "GitHub emails");
      const primary = emails.find((e) => e.primary && e.verified);
      return { id: String(u.id), email: primary?.email.toLowerCase() ?? null, emailVerified: !!primary, ...splitName(u.name), imageUrl: str(u.avatar_url) };
    },
  },

  discord: {
    async endpoints() {
      const b = t("discord");
      return { authorize: b ? `${b}/authorize` : "https://discord.com/oauth2/authorize", token: b ? `${b}/token` : "https://discord.com/api/oauth2/token", scope: "identify email", extra: { prompt: "consent" } };
    },
    async profile(_cfg, tok) {
      const api = t("discord") ? `${t("discord")}/api` : "https://discord.com/api";
      const u = await getJson<{ id: string; email?: string | null; verified?: boolean; global_name?: string | null; username?: string; avatar?: string | null }>(
        `${api}/users/@me`,
        { authorization: `Bearer ${tok.access_token}` },
        "Discord user",
      );
      const avatar = u.avatar && /^[a-f0-9_]+$/i.test(u.avatar) && /^\d+$/.test(u.id) ? `https://cdn.discordapp.com/avatars/${u.id}/${u.avatar}.png` : null;
      return { id: String(u.id), email: str(u.email)?.toLowerCase() ?? null, emailVerified: u.verified === true, firstName: str(u.global_name) ?? str(u.username), lastName: null, imageUrl: avatar };
    },
  },

  gitlab: {
    async endpoints(cfg) {
      const base = t("gitlab") ?? cfg.settings.issuer ?? "https://gitlab.com";
      return { authorize: `${base}/oauth/authorize`, token: `${base}/oauth/token`, scope: "openid email profile" };
    },
    async profile(cfg, tok) {
      const base = t("gitlab") ?? cfg.settings.issuer ?? "https://gitlab.com";
      const u = await getJson<Record<string, unknown>>(`${base}/oauth/userinfo`, { authorization: `Bearer ${tok.access_token}` }, "GitLab userinfo");
      return { id: String(u.sub), email: str(u.email)?.toLowerCase() ?? null, emailVerified: u.email_verified === true, ...splitName(u.name), imageUrl: str(u.picture) };
    },
  },

  microsoft: {
    async endpoints(cfg) {
      const tenant = cfg.settings.tenant || "common";
      const b = t("microsoft");
      const base = b ? `${b}/${tenant}` : `https://login.microsoftonline.com/${tenant}`;
      return { authorize: `${base}/oauth2/v2.0/authorize`, token: `${base}/oauth2/v2.0/token`, scope: "openid email profile", extra: { prompt: "select_account" } };
    },
    async profile(cfg, tok, ctx) {
      const tenant = cfg.settings.tenant || "common";
      const b = t("microsoft");
      const root = b ?? "https://login.microsoftonline.com";
      const c = await verifyIdToken(tok.id_token, `${root}/${tenant}/discovery/v2.0/keys`, cfg.clientId, ctx.nonce);
      const tid = str(c.tid);
      // Multi-tenant tokens are issued per tenant: the issuer must name the tenant in the token.
      if (!tid || c.iss !== `${root}/${tid}/v2.0`) throw errors.badRequest("oauth_failed", "Unexpected token issuer");
      if (!["common", "organizations", "consumers"].includes(tenant) && /^[0-9a-f-]{36}$/i.test(tenant) && tid !== tenant)
        throw errors.badRequest("oauth_failed", "This account belongs to a different organization");
      const email = (str(c.email) ?? null)?.toLowerCase() ?? null;
      const emailVerified = !!email && (tid === MS_CONSUMER_TENANT || c.xms_edov === true || c.xms_edov === 1);
      const name = str(c.given_name) ? { firstName: str(c.given_name), lastName: str(c.family_name) } : splitName(c.name);
      return { id: `${tid}:${str(c.oid) ?? str(c.sub)}`, email, emailVerified, ...name, imageUrl: null };
    },
  },

  apple: {
    formPost: true,
    async endpoints() {
      const b = t("apple");
      return { authorize: b ? `${b}/authorize` : "https://appleid.apple.com/auth/authorize", token: b ? `${b}/token` : "https://appleid.apple.com/auth/token", scope: "name email", extra: { response_mode: "form_post" } };
    },
    secret: appleClientSecret,
    async profile(cfg, tok, ctx) {
      const b = t("apple");
      const iss = b ?? "https://appleid.apple.com";
      const c = await verifyIdToken(tok.id_token, `${iss}/auth/keys`, cfg.clientId, ctx.nonce, iss);
      // Apple sends the name once, on the first sign-in, as unsigned form data: cosmetic only.
      let firstName: string | null = null, lastName: string | null = null;
      try {
        const u = ctx.appleUser ? (JSON.parse(ctx.appleUser.slice(0, 2000)) as { name?: { firstName?: string; lastName?: string } }) : null;
        firstName = str(u?.name?.firstName);
        lastName = str(u?.name?.lastName);
      } catch {
        /* ignore a malformed name */
      }
      return { id: String(c.sub), email: str(c.email)?.toLowerCase() ?? null, emailVerified: truthy(c.email_verified), firstName, lastName, imageUrl: null };
    },
  },

  oidc: {
    async endpoints(cfg) {
      const d = await discover(cfg.settings.issuer!);
      return { authorize: d.authorization_endpoint, token: d.token_endpoint, scope: "openid email profile" };
    },
    async profile(cfg, tok, ctx) {
      const d = await discover(cfg.settings.issuer!);
      const c = await verifyIdToken(tok.id_token, d.jwks_uri, cfg.clientId, ctx.nonce, d.issuer);
      let claims: Record<string, unknown> = c;
      // Some providers keep email out of the ID token; ask userinfo, but only accept it for the same subject.
      if ((!c.email || c.email_verified === undefined) && d.userinfo_endpoint && tok.access_token) {
        const u = await getJson<Record<string, unknown>>(d.userinfo_endpoint, { authorization: `Bearer ${tok.access_token}` }, "userinfo");
        if (u.sub === c.sub) claims = { ...c, ...u };
      }
      const name = str(claims.given_name) ? { firstName: str(claims.given_name), lastName: str(claims.family_name) } : splitName(claims.name);
      return { id: String(c.sub), email: str(claims.email)?.toLowerCase() ?? null, emailVerified: truthy(claims.email_verified), ...name, imageUrl: str(claims.picture) };
    },
  },
};
