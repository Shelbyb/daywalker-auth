/**
 * OAuth checks against a local mock provider (no real Google/GitHub apps needed).
 * Start the service with OAUTH_TEST_BASE_URL=http://localhost:3999 (only honored on non-HTTPS deployments).
 */
import { createServer } from "node:http";
import { createHash, randomBytes } from "node:crypto";
import { sql } from "drizzle-orm";
import { seedInstance } from "./seed";
import { db, closeDb } from "../src/lib/db";
import { closeCache } from "../src/lib/cache";

const AUTH = "http://localhost:3000";
const MOCK_PORT = 3999;
const APP = "http://localhost:3001";
let failures = 0;
const check = (name: string, ok: boolean, detail?: unknown) => {
  console.log(`${ok ? "✓" : "✗"} ${name}${ok ? "" : ` — ${JSON.stringify(detail)}`}`);
  if (!ok) failures++;
};

// ---------- Mock provider ----------
type MockProfile = { id: string; email: string; verified: boolean; first?: string; last?: string };
let nextProfile: MockProfile;
const codes = new Map<string, { challenge: string; profile: MockProfile; redirectUri: string }>();
const tokens = new Map<string, MockProfile>();
const seen = { pkceOk: 0, pkceBad: 0, secretBad: 0 };
const CLIENT = { id: "mock-client-id", secret: "mock-client-secret-" + randomBytes(8).toString("hex") };

const mock = createServer(async (req, res) => {
  const url = new URL(req.url!, `http://localhost:${MOCK_PORT}`);
  const [, provider, ...rest] = url.pathname.split("/");
  const path = rest.join("/");
  const send = (status: number, body: unknown) => {
    res.writeHead(status, { "content-type": "application/json" });
    res.end(JSON.stringify(body));
  };

  if (path === "authorize") {
    const redirectUri = url.searchParams.get("redirect_uri")!;
    const back = new URL(redirectUri);
    if (url.searchParams.get("deny")) back.searchParams.set("error", "access_denied");
    else {
      const code = randomBytes(16).toString("hex");
      codes.set(code, { challenge: url.searchParams.get("code_challenge")!, profile: nextProfile, redirectUri });
      back.searchParams.set("code", code);
    }
    back.searchParams.set("state", url.searchParams.get("state")!);
    res.writeHead(302, { location: back.toString() });
    return res.end();
  }
  if (path === "token") {
    let raw = "";
    for await (const c of req) raw += c;
    const f = new URLSearchParams(raw);
    const entry = codes.get(f.get("code") ?? "");
    codes.delete(f.get("code") ?? ""); // codes are single use, like real providers
    if (f.get("client_secret") !== CLIENT.secret) return seen.secretBad++, send(401, { error: "invalid_client" });
    if (!entry || entry.redirectUri !== f.get("redirect_uri")) return send(400, { error: "invalid_grant" });
    const expected = createHash("sha256").update(f.get("code_verifier") ?? "").digest("base64url");
    if (expected !== entry.challenge) return seen.pkceBad++, send(400, { error: "invalid_grant" });
    seen.pkceOk++;
    const at = randomBytes(16).toString("hex");
    tokens.set(at, entry.profile);
    return send(200, { access_token: at, token_type: "bearer" });
  }
  const p = tokens.get(req.headers.authorization?.replace("Bearer ", "") ?? "");
  if (!p) return send(401, {});
  if (provider === "google" && path === "api/v1/userinfo")
    return send(200, { sub: p.id, email: p.email, email_verified: p.verified, given_name: p.first, family_name: p.last });
  if (provider === "github" && path === "api/user") return send(200, { id: Number(p.id), name: `${p.first ?? ""} ${p.last ?? ""}`.trim() });
  if (provider === "github" && path === "api/user/emails")
    return send(200, [{ email: p.email, primary: true, verified: p.verified }, { email: "other@example.com", primary: false, verified: true }]);
  send(404, {});
});
await new Promise<void>((r) => mock.listen(MOCK_PORT, r));

// ---------- Helpers ----------
const { publishableKey: pk, secretKey: sk, instanceId } = await seedInstance("OAuth E2E", [APP]);

class Browser {
  cookies = new Map<string, string>();
  header() {
    return [...this.cookies].map(([k, v]) => `${k}=${v}`).join("; ");
  }
  absorb(res: Response) {
    for (const c of res.headers.getSetCookie()) {
      const [kv] = c.split(";");
      const [k, v] = [kv.slice(0, kv.indexOf("=")), kv.slice(kv.indexOf("=") + 1)];
      if (/max-age=0/i.test(c) || v === "") this.cookies.delete(k);
      else this.cookies.set(k, v);
    }
  }
  async get(url: string, extra: Record<string, string> = {}) {
    const res = await fetch(url, { redirect: "manual", headers: { cookie: this.header(), ...extra } });
    this.absorb(res);
    return res;
  }
  async post(path: string, body?: unknown) {
    const res = await fetch(`${AUTH}/v1/client/${path}`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-publishable-key": pk, origin: AUTH, cookie: this.header() },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    this.absorb(res);
    return { status: res.status, body: await res.json() };
  }
}

/** Runs the whole redirect dance. Returns where the user ends up. */
async function oauth(b: Browser, provider: "google" | "github", profile: MockProfile, opts: { redirect?: string; deny?: boolean; legal?: boolean } = {}) {
  nextProfile = profile;
  const start = await b.get(`${AUTH}/v1/client/oauth/${provider}/start?pk=${pk}&redirect_url=${encodeURIComponent(opts.redirect ?? `${APP}/dashboard`)}${opts.legal ? "&legal_accepted=1" : ""}`);
  const authorize = new URL(start.headers.get("location")!);
  if (opts.deny) authorize.searchParams.set("deny", "1");
  const cb = await b.get(authorize.toString());
  const final = await b.get(cb.headers.get("location")!);
  return { start, authorize, callback: final, location: final.headers.get("location") ?? "" };
}
const whoami = async (b: Browser) => (await b.post("session/token")).body.userId as string | undefined;

// ---------- Configure providers via the backend API ----------
for (const provider of ["google", "github"]) {
  const r = await fetch(`${AUTH}/v1/instance/oauth/${provider}`, {
    method: "PUT",
    headers: { authorization: `Bearer ${sk}`, "content-type": "application/json" },
    body: JSON.stringify({ clientId: CLIENT.id, clientSecret: CLIENT.secret }),
  });
  const body = await r.json();
  check(`configure ${provider} via backend API`, r.status === 200 && body.redirectUri === `${AUTH}/v1/oauth/callback/${provider}` && !JSON.stringify(body).includes(CLIENT.secret), body);
}
const stored = JSON.stringify(await db().execute(sql`select client_secret_enc from oauth_providers where instance_id = ${instanceId}`));
check("client secret encrypted at rest", !stored.includes(CLIENT.secret));
const envBody = await (await fetch(`${AUTH}/v1/client/environment?pk=${pk}`)).json();
check("environment lists enabled providers", JSON.stringify(envBody.oauthProviders?.sort()) === '["github","google"]', envBody);
check("publishable key can't configure providers", (await fetch(`${AUTH}/v1/instance/oauth/google`, { method: "PUT", headers: { authorization: `Bearer ${pk}` } })).status === 401);

// ---------- Happy path ----------
const t = Date.now();
const alice = new Browser();
const a1 = await oauth(alice, "google", { id: `g-${t}`, email: `Alice.${t}@Example.com`, verified: true, first: "Alice", last: "Liddell" });
check("authorize URL uses PKCE S256 + state + exact redirect_uri",
  a1.authorize.searchParams.get("code_challenge_method") === "S256" && !!a1.authorize.searchParams.get("state") &&
  a1.authorize.searchParams.get("redirect_uri") === `${AUTH}/v1/oauth/callback/google`, a1.authorize.toString());
check("state cookie is HttpOnly + SameSite=Lax + path-scoped", /HttpOnly/i.test(a1.start.headers.get("set-cookie") ?? "") && /SameSite=lax/i.test(a1.start.headers.get("set-cookie") ?? "") && /Path=\/v1\/oauth/.test(a1.start.headers.get("set-cookie") ?? ""));
check("callback returns user to the app", a1.location === `${APP}/dashboard`, a1.location);
const aliceId = await whoami(alice);
check("new user signed in after OAuth", !!aliceId);
check("PKCE verifier matched at token exchange", seen.pkceOk >= 1 && seen.pkceBad === 0, seen);
const users = await (await fetch(`${AUTH}/v1/users/${aliceId}`, { headers: { authorization: `Bearer ${sk}` } })).json();
check("email normalised + marked verified, names copied", users.emailAddresses[0].email === `alice.${t}@example.com` && users.emailAddresses[0].verified && users.firstName === "Alice", users);
const ident = JSON.stringify(await db().execute(sql`select provider_user_index from oauth_accounts where user_id = ${aliceId}`));
check("provider user ID not stored in plaintext", !ident.includes(`g-${t}`));

const alice2 = new Browser();
await oauth(alice2, "google", { id: `g-${t}`, email: `alice.${t}@example.com`, verified: true });
check("same identity signs into the same user", (await whoami(alice2)) === aliceId);

// ---------- Login CSRF / replay ----------
const victim = new Browser();
const attacker = new Browser();
nextProfile = { id: `atk-${t}`, email: `mallory.${t}@example.com`, verified: true };
const s = await attacker.get(`${AUTH}/v1/client/oauth/google/start?pk=${pk}`);
const authRes = await attacker.get(s.headers.get("location")!);
const cbUrl = authRes.headers.get("location")!;
const csrf = await victim.get(cbUrl); // attacker tricks victim's browser into opening their callback URL
check("callback without the browser's state cookie is rejected (login CSRF)", csrf.status === 400 && !victim.cookies.size, csrf.status);
const legit = await attacker.get(cbUrl);
check("callback with matching state cookie succeeds", legit.status === 302);
const attacker2 = new Browser();
attacker2.cookies.set("__dw_oauth", new URL(cbUrl).searchParams.get("state")!);
check("state can't be replayed", (await attacker2.get(cbUrl)).status === 400);

// ---------- Account linking rules ----------
// Pre-registration hijack: attacker signs up with the victim's email + a password, never verifies.
const email = `victim.${t}@example.com`;
const squatter = new Browser();
const squat = await squatter.post("sign_up", { email, password: "attacker password" });
const squatId = squat.body.user.id;
const realOwner = new Browser();
await oauth(realOwner, "google", { id: `g-victim-${t}`, email, verified: true });
check("verified OAuth email links to the existing account", (await whoami(realOwner)) === squatId);
check("squatter's session revoked on link", (await squatter.post("session/token")).status === 401);
check("squatter's password removed on link", (await new Browser().post("sign_in", { email, password: "attacker password" })).body.error?.code === "invalid_credentials");

// Existing *verified* account: linking keeps the password
const bob = new Browser();
const bEmail = `bob.${t}@example.com`;
await bob.post("sign_up", { email: bEmail, password: "bob's password" });
await bob.post("email/send_code");
const { cache } = await import("../src/lib/cache");
const { blindIndex } = await import("../src/lib/crypto");
const code = (await cache().get(`devmail:${blindIndex(bEmail, "devmail")}`))!.match(/\b(\d{6})\b/)![1];
await bob.post("email/verify", { code });
const bobId = await whoami(bob);
const bobGh = new Browser();
await oauth(bobGh, "github", { id: String(t), email: bEmail, verified: true, first: "Bob" });
check("GitHub links to verified account", (await whoami(bobGh)) === bobId);
check("verified account keeps its password and sessions", (await bob.post("session/token")).status === 200 && (await new Browser().post("sign_in", { email: bEmail, password: "bob's password" })).status === 200);

// Unverified provider email is never trusted
const eve = new Browser();
const e1 = await oauth(eve, "github", { id: String(t + 1), email: bEmail, verified: false });
check("unverified provider email → error, no takeover", e1.location.includes("error=email_unverified") && !(await whoami(eve)), e1.location);

// ---------- Other paths ----------
const c = new Browser();
const cancelled = await oauth(c, "google", { id: "x", email: "x@example.com", verified: true }, { deny: true });
check("cancel at provider → back to sign-in with error", cancelled.location.includes("/sign-in?") && cancelled.location.includes("error=oauth_cancelled"), cancelled.location);
const d = new Browser();
const evil = await oauth(d, "google", { id: `g-d-${t}`, email: `dee.${t}@example.com`, verified: true }, { redirect: "https://evil.example/steal" });
check("foreign redirect_url dropped (no open redirect)", !evil.location.includes("evil.example") && evil.location.startsWith(`${AUTH}/sign-in`), evil.location);
check("unknown provider → 404", (await fetch(`${AUTH}/v1/client/oauth/myspace/start?pk=${pk}`, { redirect: "manual" })).status === 404);
check("error page messages are fixed, not reflected", !(await (await fetch(`${AUTH}/sign-in?pk=${pk}&error=%3Cscript%3Ealert(1)%3C%2Fscript%3E`)).text()).includes("<script>alert(1)"));
check("client secret never sent to the browser", !(await (await fetch(`${AUTH}/sign-in?pk=${pk}`)).text()).includes(CLIENT.secret));

// ---------- Social sign-in + 2FA ----------
const { totpAt, currentCounter } = await import("../src/lib/auth/totp");
const enroll = await alice.post("mfa/totp");
const cc = currentCounter();
await alice.post("mfa/totp/verify", { code: totpAt(enroll.body.secret, cc) });
const alice3 = new Browser();
const viaGoogle = await oauth(alice3, "google", { id: `g-${t}`, email: `alice.${t}@example.com`, verified: true });
check("2FA account: social sign-in stops at the second-factor page", viaGoogle.location.startsWith(`${AUTH}/second-factor?`) && !(await whoami(alice3)), viaGoogle.location);
const fin = await alice3.post("sign_in/second_factor", { code: totpAt(enroll.body.secret, cc + 1) });
check("…and completes with an authenticator code", fin.status === 200 && (await whoami(alice3)) === aliceId, fin.body);

// ---------- Terms acceptance for new social accounts ----------
await fetch(`${AUTH}/v1/instance/legal`, {
  method: "PUT",
  headers: { authorization: `Bearer ${sk}`, "content-type": "application/json" },
  body: JSON.stringify({ required: true, termsUrl: "https://example.com/terms", privacyUrl: null, version: "tos-1" }),
});
const n1 = new Browser();
const noConsent = await oauth(n1, "google", { id: `g-new-${t}`, email: `newbie.${t}@example.com`, verified: true });
check("new social account without consent → sent to sign-up with legal_required", noConsent.location.startsWith(`${AUTH}/sign-up?`) && noConsent.location.includes("error=legal_required") && !(await whoami(n1)), noConsent.location);
const n2 = new Browser();
await oauth(n2, "google", { id: `g-new-${t}`, email: `newbie.${t}@example.com`, verified: true }, { legal: true });
const newId = await whoami(n2);
const acc = await db().execute(sql`select version, method from legal_acceptances where user_id = ${newId ?? ""}`);
check("…with consent → created, acceptance recorded (method google)", !!newId && acc[0]?.version === "tos-1" && acc[0]?.method === "google", acc);
const existing = new Browser();
await oauth(existing, "github", { id: String(t), email: bEmail, verified: true });
check("existing user signs in with a provider without re-accepting", (await whoami(existing)) === bobId);

mock.close();
await closeDb();
await closeCache();
console.log(failures ? `\n${failures} check(s) failed` : "\nAll OAuth checks passed");
process.exit(failures ? 1 : 0);
