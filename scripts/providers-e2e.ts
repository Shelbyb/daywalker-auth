/**
 * Microsoft, Apple, Discord, GitLab and generic OpenID Connect against a local mock (port 3999)
 * that signs real ID tokens. Start the service with OAUTH_TEST_BASE_URL=http://localhost:3999,
 * WEBHOOK_ALLOW_PRIVATE=1 and ALLOW_INSECURE_TRANSPORT=1.
 */
import { createServer } from "node:http";
import { createHash, randomBytes } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { KeyObject } from "node:crypto";
import { exportJWK, exportPKCS8, generateKeyPair, importJWK, jwtVerify, SignJWT, type JWK } from "jose";
import { seedInstance } from "./seed";
import { closeDb } from "../src/lib/db";
import { closeCache } from "../src/lib/cache";
import { checkPublicUrl } from "../src/lib/net-guard";

const AUTH = "http://localhost:3000";
const MOCK = "http://localhost:3999";
const APP = "http://localhost:3001";
let failures = 0;
const check = (name: string, ok: boolean, detail?: unknown) => {
  console.log(`${ok ? "✓" : "✗"} ${name}${ok ? "" : ` — ${JSON.stringify(detail)?.slice(0, 400)}`}`);
  if (!ok) failures++;
};

// ---------- Keys ----------
// The mock's signing key is kept between runs: the service caches provider keys, and refetches
// at most every 30 seconds, so back-to-back runs with new keys would look like a key rotation.
const keyFile = join(tmpdir(), "daywalker-mock-idp.json");
let idp: { privateKey: CryptoKey | KeyObject; publicKey: CryptoKey | KeyObject };
if (existsSync(keyFile)) {
  const k = JSON.parse(readFileSync(keyFile, "utf8")) as JWK;
  idp = { privateKey: (await importJWK(k, "ES256")) as CryptoKey, publicKey: (await importJWK({ kty: k.kty, crv: k.crv, x: k.x, y: k.y }, "ES256")) as CryptoKey };
} else {
  idp = await generateKeyPair("ES256", { extractable: true });
  writeFileSync(keyFile, JSON.stringify(await exportJWK(idp.privateKey)), { mode: 0o600 });
}
const idpJwk: JWK = { ...(await exportJWK(idp.publicKey)), kid: "mock-1", alg: "ES256", use: "sig" };
const rogue = await generateKeyPair("ES256"); // signs tokens the mock doesn't publish
const apple = await generateKeyPair("ES256", { extractable: true }); // the developer's .p8 key
const appleP8 = await exportPKCS8(apple.privateKey);
const TEAM = "TEAM123456", KEY = "KEYID12345";
const CLIENT = { id: "mock-client", secret: "mock-secret-" + randomBytes(6).toString("hex") };
const MS_CONSUMER = "9188040d-6c67-4c5b-b112-36a304b66dad";
const MS_WORK = "11111111-2222-3333-4444-555555555555";

// ---------- Mock identity providers ----------
type P = { sub: string; email: string; verified: boolean; first?: string; last?: string; tid?: string; edov?: boolean };
let next: P;
let tamper: null | "nonce" | "key" | "issuer" | "audience" = null;
const codes = new Map<string, { provider: string; challenge: string | null; nonce: string | null; profile: P; redirectUri: string }>();
const tokens = new Map<string, P>();
const seen = { appleSecretOk: 0, appleSecretBad: 0, pkceBad: 0 };

async function idToken(provider: string, nonce: string | null, p: P) {
  const iss =
    tamper === "issuer" ? `${MOCK}/evil` : provider === "microsoft" ? `${MOCK}/microsoft/${p.tid}/v2.0` : provider === "apple" ? `${MOCK}/apple` : `${MOCK}/oidc`;
  const claims: Record<string, unknown> = { nonce: tamper === "nonce" ? "wrong-nonce" : nonce, email: p.email, email_verified: provider === "apple" ? String(p.verified) : p.verified };
  if (provider === "microsoft") Object.assign(claims, { tid: p.tid, oid: p.sub, name: `${p.first ?? ""} ${p.last ?? ""}`.trim(), ...(p.edov ? { xms_edov: true } : {}) });
  if (provider === "oidc") Object.assign(claims, { given_name: p.first, family_name: p.last });
  return new SignJWT(claims)
    .setProtectedHeader({ alg: "ES256", kid: "mock-1" })
    .setIssuer(iss)
    .setSubject(p.sub)
    .setAudience(tamper === "audience" ? "someone-else" : CLIENT.id)
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(tamper === "key" ? rogue.privateKey : idp.privateKey);
}

const mock = createServer(async (req, res) => {
  const url = new URL(req.url!, MOCK);
  const parts = url.pathname.split("/").filter(Boolean);
  const provider = parts[0];
  const path = parts.slice(1).join("/");
  const send = (status: number, body: unknown) => res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(body));

  // Discovery and key sets
  if (url.pathname === "/oidc/.well-known/openid-configuration")
    return send(200, { issuer: `${MOCK}/oidc`, authorization_endpoint: `${MOCK}/oidc/authorize`, token_endpoint: `${MOCK}/oidc/token`, userinfo_endpoint: `${MOCK}/oidc/userinfo`, jwks_uri: `${MOCK}/oidc/jwks` });
  if (url.pathname === "/liar/.well-known/openid-configuration")
    return send(200, { issuer: `${MOCK}/oidc`, authorization_endpoint: `${MOCK}/oidc/authorize`, token_endpoint: `${MOCK}/oidc/token`, jwks_uri: `${MOCK}/oidc/jwks` });
  if (path === "jwks" || path === "auth/keys" || path.endsWith("discovery/v2.0/keys")) return send(200, { keys: [idpJwk] });

  if (path.endsWith("authorize")) {
    const redirectUri = url.searchParams.get("redirect_uri")!;
    const code = randomBytes(12).toString("hex");
    codes.set(code, { provider, challenge: url.searchParams.get("code_challenge"), nonce: url.searchParams.get("nonce"), profile: next, redirectUri });
    const state = url.searchParams.get("state")!;
    if (provider === "apple") return send(200, { formPost: true, redirectUri, code, state, mode: url.searchParams.get("response_mode") });
    const back = new URL(redirectUri);
    back.searchParams.set("code", code);
    back.searchParams.set("state", state);
    return res.writeHead(302, { location: back.toString() }).end();
  }
  if (path.endsWith("token")) {
    let raw = "";
    for await (const c of req) raw += c;
    const f = new URLSearchParams(raw);
    const entry = codes.get(f.get("code") ?? "");
    codes.delete(f.get("code") ?? "");
    if (!entry || entry.redirectUri !== f.get("redirect_uri") || f.get("client_id") !== CLIENT.id) return send(400, { error: "invalid_grant" });
    if (provider === "apple") {
      // Apple's client secret is a JWT signed with the developer's key.
      try {
        const { payload, protectedHeader } = await jwtVerify(f.get("client_secret") ?? "", apple.publicKey, { audience: "https://appleid.apple.com", issuer: TEAM, subject: CLIENT.id });
        if (protectedHeader.kid !== KEY || (payload.exp ?? 0) - (payload.iat ?? 0) > 3600) throw new Error("bad");
        seen.appleSecretOk++;
      } catch {
        seen.appleSecretBad++;
        return send(401, { error: "invalid_client" });
      }
    } else {
      if (f.get("client_secret") !== CLIENT.secret) return send(401, { error: "invalid_client" });
      const expected = createHash("sha256").update(f.get("code_verifier") ?? "").digest("base64url");
      if (entry.challenge && expected !== entry.challenge) return seen.pkceBad++, send(400, { error: "invalid_grant" });
    }
    const at = randomBytes(12).toString("hex");
    tokens.set(at, entry.profile);
    const withId = ["microsoft", "apple", "oidc"].includes(provider);
    return send(200, { access_token: at, token_type: "Bearer", ...(withId ? { id_token: await idToken(provider, entry.nonce, entry.profile) } : {}) });
  }
  const p = tokens.get(req.headers.authorization?.replace("Bearer ", "") ?? "");
  if (!p) return send(401, {});
  if (provider === "discord" && path === "api/users/@me") return send(200, { id: p.sub, email: p.email, verified: p.verified, global_name: p.first, username: "user", avatar: null });
  if (provider === "gitlab" && path === "oauth/userinfo") return send(200, { sub: p.sub, email: p.email, email_verified: p.verified, name: `${p.first ?? ""} ${p.last ?? ""}`.trim() });
  if (provider === "oidc" && path === "userinfo") return send(200, { sub: p.sub, email: p.email, email_verified: p.verified });
  send(404, {});
});
await new Promise<void>((r) => mock.listen(3999, r));

// ---------- Browser ----------
class Browser {
  cookies = new Map<string, string>();
  header() {
    return [...this.cookies].map(([k, v]) => `${k}=${v}`).join("; ");
  }
  absorb(res: Response) {
    for (const c of res.headers.getSetCookie()) {
      const [kv] = c.split(";");
      const k = kv.slice(0, kv.indexOf("=")), v = kv.slice(kv.indexOf("=") + 1);
      if (/max-age=0/i.test(c) || v === "") this.cookies.delete(k);
      else this.cookies.set(k, v);
    }
  }
  async get(url: string) {
    const res = await fetch(url, { redirect: "manual", headers: { cookie: this.header() } });
    this.absorb(res);
    return res;
  }
  async postForm(url: string, form: Record<string, string>) {
    const res = await fetch(url, { method: "POST", redirect: "manual", headers: { cookie: this.header(), "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(form).toString() });
    this.absorb(res);
    return res;
  }
  async token(pk: string) {
    const res = await fetch(`${AUTH}/v1/client/session/token`, { method: "POST", headers: { "x-publishable-key": pk, origin: AUTH, cookie: this.header() } });
    return (await res.json()).userId as string | undefined;
  }
}

const seed = await seedInstance("Providers E2E", [APP]);
const { publishableKey: pk, secretKey: sk } = seed;
const configure = (provider: string, body: Record<string, unknown>, key = sk) =>
  fetch(`${AUTH}/v1/instance/oauth/${provider}`, { method: "PUT", headers: { authorization: `Bearer ${key}`, "content-type": "application/json" }, body: JSON.stringify(body) });

/** Full flow. Returns the final redirect target and the browser. */
async function signIn(provider: string, profile: P, opts: { pk?: string; appleUser?: unknown } = {}) {
  next = profile;
  const b = new Browser();
  const key = opts.pk ?? pk;
  const start = await b.get(`${AUTH}/v1/client/oauth/${provider}/start?pk=${key}&redirect_url=${encodeURIComponent(`${APP}/home`)}`);
  const authorize = new URL(start.headers.get("location") ?? `${AUTH}/missing`);
  let cb: Response;
  if (provider === "apple") {
    const a = await (await fetch(authorize)).json();
    cb = await b.postForm(a.redirectUri, { code: a.code, state: a.state, ...(opts.appleUser ? { user: JSON.stringify(opts.appleUser) } : {}) });
    return { b, authorize, apple: a, location: cb.headers.get("location") ?? "", status: cb.status, userId: await b.token(key) };
  }
  const mid = await b.get(authorize.toString());
  cb = await b.get(mid.headers.get("location")!);
  return { b, authorize, location: cb.headers.get("location") ?? "", status: cb.status, userId: await b.token(key) };
}
const user = async (id: string) => (await fetch(`${AUTH}/v1/users/${id}`, { headers: { authorization: `Bearer ${sk}` } })).json();
const errOf = (loc: string) => new URL(loc, AUTH).searchParams.get("error");

// ---------- Configuration ----------
check("OIDC without an issuer is rejected", (await configure("oidc", { clientId: CLIENT.id, clientSecret: CLIENT.secret })).status === 422);
check("Apple needs a real .p8 key", (await configure("apple", { clientId: CLIENT.id, clientSecret: "not-a-key", settings: { teamId: TEAM, keyId: KEY } })).status === 400);
check("Apple needs a Team ID and Key ID", (await configure("apple", { clientId: CLIENT.id, clientSecret: appleP8 })).status === 422);
check("Microsoft tenant must look like a tenant", (await configure("microsoft", { clientId: CLIENT.id, clientSecret: CLIENT.secret, settings: { tenant: "../../evil" } })).status === 422);
const cfgs: [string, Record<string, unknown>][] = [
  ["microsoft", { clientId: CLIENT.id, clientSecret: CLIENT.secret }],
  ["apple", { clientId: CLIENT.id, clientSecret: appleP8, settings: { teamId: TEAM, keyId: KEY } }],
  ["discord", { clientId: CLIENT.id, clientSecret: CLIENT.secret }],
  ["gitlab", { clientId: CLIENT.id, clientSecret: CLIENT.secret }],
  ["oidc", { clientId: CLIENT.id, clientSecret: CLIENT.secret, settings: { issuer: `${MOCK}/oidc/`, displayName: "Acme SSO" } }],
];
for (const [p, body] of cfgs) {
  const r = await configure(p, body);
  const j = await r.json();
  check(`configure ${p}`, r.status === 200 && !JSON.stringify(j).includes(String(body.clientSecret)), j);
}
const envBody = await (await fetch(`${AUTH}/v1/client/environment?pk=${pk}`)).json();
check("environment lists the providers with labels (custom OIDC name)", envBody.oauthProviders.length === 5 && envBody.oauthProviderLabels.oidc === "Acme SSO" && envBody.oauthProviderLabels.microsoft === "Microsoft", envBody);
const page = (await (await fetch(`${AUTH}/sign-in?pk=${pk}`)).text()).replace(/<!-- -->/g, "");
check("hosted sign-in shows the new buttons", ["Continue with Microsoft", "Continue with Apple", "Continue with Discord", "Continue with GitLab", "Continue with Acme SSO"].every((t) => page.includes(t)));

const t = Date.now();
// ---------- Discord ----------
const d1 = await signIn("discord", { sub: `${t}1`, email: `Dee.${t}@example.com`, verified: true, first: "Dee" });
check("Discord: signs in and lands on the app", d1.location === `${APP}/home` && !!d1.userId, d1.location);
check("Discord: PKCE used", d1.authorize.searchParams.get("code_challenge_method") === "S256");
const du = await user(d1.userId!);
check("Discord: verified email and name copied", du.emailAddresses[0].email === `dee.${t}@example.com` && du.emailAddresses[0].verified && du.firstName === "Dee", du);
const d2 = await signIn("discord", { sub: `${t}2`, email: `unverified.${t}@example.com`, verified: false });
check("Discord: unverified email → refused", errOf(d2.location) === "email_unverified" && !d2.userId, d2.location);
const d3 = await signIn("discord", { sub: `${t}1`, email: `changed.${t}@example.com`, verified: true });
check("Discord: same account later signs into the same user", d3.userId === d1.userId);

// ---------- GitLab ----------
const g1 = await signIn("gitlab", { sub: `gl-${t}`, email: `gil.${t}@example.com`, verified: true, first: "Gil", last: "Lab" });
check("GitLab: signs in", !!g1.userId && (await user(g1.userId!)).lastName === "Lab");

// ---------- Microsoft ----------
const m1 = await signIn("microsoft", { sub: `oid-${t}a`, email: `max.${t}@outlook.com`, verified: true, tid: MS_CONSUMER, first: "Max", last: "Soft" });
check("Microsoft personal account: signs in with a nonce-bound ID token", !!m1.userId && !!m1.authorize.searchParams.get("nonce"), m1.location);
const m2 = await signIn("microsoft", { sub: `oid-${t}b`, email: `ceo.${t}@victim.example`, verified: true, tid: MS_WORK });
check("Microsoft work account WITHOUT a verified domain → email not trusted (nOAuth)", errOf(m2.location) === "email_unverified" && !m2.userId, m2.location);
const m3 = await signIn("microsoft", { sub: `oid-${t}c`, email: `dev.${t}@verified.example`, verified: true, tid: MS_WORK, edov: true });
check("Microsoft work account with xms_edov → trusted", !!m3.userId);
tamper = "issuer";
const m4 = await signIn("microsoft", { sub: `oid-${t}d`, email: `x.${t}@outlook.com`, verified: true, tid: MS_CONSUMER });
check("Microsoft: token from the wrong issuer → refused", errOf(m4.location) === "oauth_failed" && !m4.userId);
tamper = null;

// ---------- Apple ----------
const a1 = await signIn("apple", { sub: `apple-${t}`, email: `relay.${t}@privaterelay.appleid.com`, verified: true }, { appleUser: { name: { firstName: "Ann", lastName: "Apple" } } });
check("Apple: asks for form_post, no PKCE", a1.apple.mode === "form_post" && !a1.authorize.searchParams.get("code_challenge"));
check("Apple: callback by form POST signs in", a1.status === 302 && a1.location === `${APP}/home` && !!a1.userId, a1);
check("Apple: client secret is a short-lived JWT signed with the developer's key", seen.appleSecretOk >= 1 && seen.appleSecretBad === 0, seen);
check("Apple: name from the first sign-in is kept", (await user(a1.userId!)).firstName === "Ann");
check("POST callback is only accepted for Apple", (await fetch(`${AUTH}/v1/oauth/callback/google`, { method: "POST" })).status === 405);

// ---------- Generic OIDC ----------
const o1 = await signIn("oidc", { sub: `okta-${t}`, email: `olive.${t}@acme.example`, verified: true, first: "Olive", last: "Okta" });
check("OIDC: discovery, ID token and sign-in work", !!o1.userId && (await user(o1.userId!)).firstName === "Olive", o1.location);
for (const kind of ["nonce", "key", "audience"] as const) {
  tamper = kind;
  const r = await signIn("oidc", { sub: `okta-${t}-${kind}`, email: `t.${kind}.${t}@acme.example`, verified: true });
  check(`OIDC: tampered ID token (${kind}) → refused`, errOf(r.location) === "oauth_failed" && !r.userId, r.location);
}
tamper = null;
const o2 = await signIn("oidc", { sub: `okta-${t}-unv`, email: `unv.${t}@acme.example`, verified: false });
check("OIDC: email_verified false → refused", errOf(o2.location) === "email_unverified");

// A discovery document that claims a different issuer than the one configured
const liar = await seedInstance("Providers E2E (liar)", [APP]);
await configure("oidc", { clientId: CLIENT.id, clientSecret: CLIENT.secret, settings: { issuer: `${MOCK}/liar` } }, liar.secretKey);
const l1 = await new Browser().get(`${AUTH}/v1/client/oauth/oidc/start?pk=${liar.publishableKey}`);
check("OIDC: discovery with a mismatched issuer is refused", l1.status === 400 && !(l1.headers.get("location") ?? "").includes("/oidc/authorize"), l1.status);

// ---------- SSRF guard (in-process, test switches off) ----------
const saved = process.env.WEBHOOK_ALLOW_PRIVATE;
delete process.env.WEBHOOK_ALLOW_PRIVATE;
const blocked = await Promise.all(["https://127.0.0.1/", "https://169.254.169.254/latest", "https://10.0.0.5/", "https://[::1]/"].map((u) => checkPublicUrl(u)));
check("issuer and endpoint URLs can't point at private or metadata addresses", blocked.every((r) => !r.ok && r.problem === "private"), blocked);
process.env.WEBHOOK_ALLOW_PRIVATE = saved;

mock.close();
await closeDb();
await closeCache();
console.log(failures ? `\n${failures} check(s) failed` : "\nAll social provider checks passed");
process.exit(failures ? 1 : 0);
