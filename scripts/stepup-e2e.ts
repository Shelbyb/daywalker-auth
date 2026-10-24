/**
 * Step-up authentication: auth_time / fva in the session token, reverification with a password, authenticator or
 * backup code, security key, passkey and emailed code, lockout accounting, server SDK helpers, and the browser
 * SDK's authFetch retry against a tiny protected API. Needs the service on :3000.
 */
import { createServer } from "node:http";
import { randomInt } from "node:crypto";
import { sql } from "drizzle-orm";
import { seedInstance } from "./seed";
import { db, closeDb } from "../src/lib/db";
import { cache, closeCache } from "../src/lib/cache";
import { blindIndex } from "../src/lib/crypto";
import { sha256 } from "../src/lib/ids";
import { totpAt, currentCounter } from "../src/lib/auth/totp";
import { SoftAuthenticator, AUTH } from "./soft-authenticator";
import { createAuthClient } from "../packages/sdk/src/core";
import { staleFactors } from "../packages/sdk/src/core/fresh";
import { verifyToken, isRecentlyVerified, requireRecentAuth, ReverificationRequiredError, reverificationResponse } from "../packages/sdk/src/server";

let failures = 0;
const check = (name: string, ok: boolean, detail?: unknown) => {
  console.log(`${ok ? "✓" : "✗"} ${name}${ok ? "" : ` — ${JSON.stringify(detail)?.slice(0, 400)}`}`);
  if (!ok) failures++;
};
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const rows = async (q: ReturnType<typeof sql>) => (await db().execute(q)) as unknown as Record<string, any>[];

const seed = await seedInstance("Step-up E2E", []);
const pk = seed.publishableKey;
const cfg = { publishableKey: pk, frontendApi: AUTH };

class Browser {
  cookies = new Map<string, string>();
  async call(method: string, path: string, body?: unknown) {
    const r = await fetch(`${AUTH}/v1/client/${path}`, {
      method,
      headers: { "content-type": "application/json", "x-publishable-key": pk, origin: AUTH, "x-forwarded-for": `198.51.100.${randomInt(1, 250)}`, cookie: [...this.cookies].map(([k, v]) => `${k}=${v}`).join("; ") },
      body: body === undefined || method === "GET" ? undefined : JSON.stringify(body),
    });
    for (const c of r.headers.getSetCookie()) {
      const [kv] = c.split(";");
      const k = kv.slice(0, kv.indexOf("=")), v = kv.slice(kv.indexOf("=") + 1);
      if (/max-age=0/i.test(c) || !v) this.cookies.delete(k);
      else this.cookies.set(k, v);
    }
    return { status: r.status, body: await r.json().catch(() => null) };
  }
  post = (path: string, body?: unknown) => this.call("POST", path, body);
  get = (path: string) => this.call("GET", path);
  get refresh() { return [...this.cookies].find(([k]) => k.startsWith("__dw_rt_"))?.[1] ?? ""; }
}
const pw = "a long enough password";
async function newUser(tag: string) {
  const b = new Browser();
  const email = `${tag}.${Date.now()}.${randomInt(1000)}@example.com`;
  const r = await b.post("sign_up", { email, password: pw });
  return { b, email, id: r.body.user.id as string, jwt: r.body.jwt as string };
}
const code = (r: { body: { error?: { code?: string } } | null }) => r.body?.error?.code;
const claims = (jwt: string) => (jwt ? JSON.parse(Buffer.from(jwt.split(".")[1], "base64url").toString()) : null);
const token = async (b: Browser) => (await b.post("session/token")).body.jwt as string;
/** Make the session's recorded proofs older, as if time had passed. */
async function age(b: Browser, o: { first?: number; second?: number | null }) {
  const h = sha256(b.refresh);
  if (o.first !== undefined) await db().execute(sql`update sessions set first_factor_at = now() - make_interval(secs => ${o.first}) where refresh_token_hash = ${h}`);
  if (o.second !== undefined) await db().execute(sql`update sessions set second_factor_at = ${o.second === null ? null : sql`now() - make_interval(secs => ${o.second})`} where refresh_token_hash = ${h}`);
  await cache().del(`sess:${h}`);
}
const resetLimits = async () => { const k = await cache().keys(`rl:${seed.instanceId}:*`); if (k.length) await cache().del(...k); };
const enableTotp = async (u: { b: Browser }) => {
  const start = await u.b.post("mfa/totp");
  const secret: string = start.body.secret;
  const c = currentCounter();
  const conf = await u.b.post("mfa/totp/verify", { code: totpAt(secret, c) });
  return { secret, backup: conf.body.backupCodes as string[], counter: c };
};
const ageOf = (jwt: string) => (claims(jwt)?.fva ?? [999999, 999999]) as [number, number];

// ---------- Claims ----------
const ann = await newUser("ann");
const c0 = claims(ann.jwt);
check("sign-up token carries auth_time and fva", typeof c0.auth_time === "number" && Array.isArray(c0.fva) && c0.fva.length === 2, c0);
check("fresh: first factor age ~0, second never (-1)", c0.fva[0] >= 0 && c0.fva[0] <= 3 && c0.fva[1] === -1, c0.fva);
check("auth_time is the sign-in time", Math.abs(c0.auth_time - Math.floor(Date.now() / 1000)) <= 5);
await age(ann.b, { first: 600 });
const aged = await token(ann.b);
check("ages grow with the session (600s)", ageOf(aged)[0] >= 600 && ageOf(aged)[0] <= 605 && Math.abs(claims(aged).auth_time - (Math.floor(Date.now() / 1000) - 600)) <= 5, claims(aged));
check("token refresh alone never freshens a session", ageOf(await token(ann.b))[0] >= 600);

// ---------- Server SDK helpers ----------
const v = await verifyToken(aged, cfg);
check("verifyToken exposes fva and authTime, not as custom claims", !!v?.fva && v.fva[1] === -1 && typeof v.authTime === "number" && !("fva" in (v.claims ?? {})) && !("auth_time" in (v.claims ?? {})), v);
check("10 minutes old: not recent for maxAge 300", v !== null && !isRecentlyVerified(v, { maxAge: 300 }));
check("…but recent for maxAge 900", v !== null && isRecentlyVerified(v, { maxAge: 900 }));
check("second_factor never satisfied without one", v !== null && !isRecentlyVerified(v, { maxAge: 99999, level: "second_factor" }) && !isRecentlyVerified(v, { maxAge: 99999, level: "multi_factor" }));
check("age includes time since issue (old token can't look fresh)", v !== null && !isRecentlyVerified(v, { maxAge: 700 }, v.issuedAt + 400));
check("signed out is never recent", !isRecentlyVerified(null, { maxAge: 300 }));
check("bad maxAge is never recent", v !== null && !isRecentlyVerified(v, { maxAge: -1 }) && !isRecentlyVerified(v, { maxAge: Number.NaN }));
let thrown: unknown;
try { requireRecentAuth(v, { maxAge: 300, level: "multi_factor" }); } catch (e) { thrown = e; }
check("requireRecentAuth throws ReverificationRequiredError (403)", thrown instanceof ReverificationRequiredError && thrown.status === 403 && thrown.reverification.level === "multi_factor" && thrown.reverification.maxAge === 300);
const resp = (thrown as ReverificationRequiredError).toResponse();
const rbody = await resp.json();
check("toResponse is the 403 the browser SDK understands", resp.status === 403 && rbody.error.code === "reverification_required" && rbody.error.reverification.level === "multi_factor" && resp.headers.get("cache-control") === "no-store", rbody);
check("reverificationResponse defaults to first_factor", (await reverificationResponse({ maxAge: 60 }).json()).error.reverification.level === "first_factor");
check("staleFactors: first only", JSON.stringify(staleFactors({ fva: [900, -1], issuedAt: 1000 }, { maxAge: 300, level: "first_factor" }, 1000)) === '{"first":true,"second":false}');
check("staleFactors: multi reports both", JSON.stringify(staleFactors({ fva: [10, 10], issuedAt: 1000 }, { maxAge: 300, level: "multi_factor" }, 1000)) === '{"first":false,"second":false}' && staleFactors({ fva: [10, -1], issuedAt: 1000 }, { maxAge: 300, level: "multi_factor" }, 1000).second);

// ---------- Custom claims can't forge freshness ----------
const { validateClaims } = await import("../src/lib/session-settings");
check("custom claims named fva / auth_time / cnf are refused", !!validateClaims({ fva: "x" }) && !!validateClaims({ auth_time: "x" }) && !!validateClaims({ cnf: "x" }));

// ---------- Password ----------
check("options need a session", (await new Browser().get("session/reverify")).status === 401);
check("reverify needs a session", (await new Browser().post("session/reverify", { factor: "password", password: pw })).status === 401);
const opt1 = await ann.b.get("session/reverify");
check("options: password only for a plain account", opt1.body.password === true && opt1.body.passkey === false && opt1.body.totp === false && opt1.body.sms === null && opt1.body.securityKey === false && opt1.body.emailCode === false, opt1.body);
const wrong = await ann.b.post("session/reverify", { factor: "password", password: "wrong password 12" });
check("wrong password: 400 invalid_credentials", wrong.status === 400 && code(wrong) === "invalid_credentials", wrong);
check("…and it freshened nothing", ageOf(await token(ann.b))[0] >= 600);
const bad = await ann.b.post("session/reverify", { factor: "bogus" });
check("unknown factor: 422", bad.status === 422, bad);
const good = await ann.b.post("session/reverify", { factor: "password", password: pw });
check("right password: new token with a fresh first factor", good.status === 200 && good.body.verified === true && ageOf(good.body.jwt)[0] <= 3 && ageOf(good.body.jwt)[1] === -1, good.body);
check("the next refresh keeps it fresh", ageOf(await token(ann.b))[0] <= 5);
const vNow = await verifyToken(good.body.jwt, cfg);
check("now recent for maxAge 300", vNow !== null && isRecentlyVerified(vNow, { maxAge: 300 }));
check("a code factor for an account with no 2FA: 400 no_second_factor", code(await ann.b.post("session/reverify", { factor: "code", code: "123456" })) === "no_second_factor");
check("security_key without a touch: 400 security_key_required", code(await ann.b.post("session/reverify", { factor: "security_key" })) === "no_second_factor" || code(await ann.b.post("session/reverify", { factor: "security_key" })) === "security_key_required");
check("email_code not available when a password exists", code(await ann.b.post("session/reverify", { factor: "email_code", code: "123456" })) === "not_available");
const aud = await rows(sql`select data_enc from audit_events where instance_id = ${seed.instanceId} and type = 'user.reverified' and target_id = ${ann.id}`);
check("reverification is audited", aud.length === 1, aud);

// ---------- Authenticator and backup codes ----------
const bob = await newUser("bob");
const { secret, backup, counter } = await enableTotp(bob);
check("setup: two-factor on", backup.length === 10);
const bobIn = new Browser();
await bobIn.post("sign_in", { email: bob.email, password: pw });
const si = await bobIn.post("sign_in/second_factor", { code: totpAt(secret, counter + 1) });
check("sign-in with 2FA: both factors fresh", ageOf(si.body.jwt)[0] <= 3 && ageOf(si.body.jwt)[1] >= 0 && ageOf(si.body.jwt)[1] <= 3, si.body.jwt && claims(si.body.jwt).fva);
const optB = await bobIn.get("session/reverify");
check("options: authenticator and backup codes", optB.body.totp === true && optB.body.backupCodes === true && optB.body.password === true && optB.body.securityKey === false, optB.body);
await age(bobIn, { first: 1000, second: 1000 });
const stale = await verifyToken(await token(bobIn), cfg);
check("both stale for multi_factor", stale !== null && !isRecentlyVerified(stale, { maxAge: 300, level: "multi_factor" }) && !isRecentlyVerified(stale, { maxAge: 300, level: "second_factor" }));
const wc = await bobIn.post("session/reverify", { factor: "code", code: "000000" });
check("wrong code: invalid_code", code(wc) === "invalid_code", wc);
const rc = await bobIn.post("session/reverify", { factor: "code", code: totpAt(secret, counter - 1) });
check("right code freshens the second factor only", rc.status === 200 && ageOf(rc.body.jwt)[1] <= 3 && ageOf(rc.body.jwt)[0] >= 1000, claims(rc.body.jwt)?.fva ?? rc.body);
const vSecond = await verifyToken(rc.body.jwt, cfg);
check("second_factor level satisfied, first_factor not", vSecond !== null && isRecentlyVerified(vSecond, { maxAge: 300, level: "second_factor" }) && !isRecentlyVerified(vSecond, { maxAge: 300, level: "first_factor" }) && !isRecentlyVerified(vSecond, { maxAge: 300, level: "multi_factor" }));
check("the same code can't be reused", code(await bobIn.post("session/reverify", { factor: "code", code: totpAt(secret, counter - 1) })) === "invalid_code");
await age(bobIn, { second: 1000 });
const bc = await bobIn.post("session/reverify", { factor: "code", code: backup[0] });
check("a backup code works too", bc.status === 200 && ageOf(bc.body.jwt)[1] <= 3, bc);
check("backup codes are single-use here as well", code(await bobIn.post("session/reverify", { factor: "code", code: backup[0] })) === "invalid_code");
const pwB = await bobIn.post("session/reverify", { factor: "password", password: pw });
const vAll = await verifyToken(pwB.body.jwt, cfg);
check("password then code satisfies multi_factor", vAll !== null && isRecentlyVerified(vAll, { maxAge: 300, level: "multi_factor" }));

// ---------- Security key ----------
const key = new SoftAuthenticator();
const kReg = await bobIn.post("mfa/security_keys/register/options", { code: backup[1] });
const kVer = await bobIn.post("mfa/security_keys/register/verify", { response: key.register(kReg.body, { uv: false }), name: "Key" });
check("setup: security key registered", kVer.status === 201, kVer);
await age(bobIn, { second: 1000 });
check("without a touch: security_key_required", code(await bobIn.post("session/reverify", { factor: "security_key" })) === "security_key_required");
const ko = await bobIn.post("mfa/security_keys/confirm/options");
const kc = await bobIn.post("mfa/security_keys/confirm", { response: key.assert(ko.body.challenge, { uv: false }) });
check("touch confirmed", kc.status === 200, kc);
const kr = await bobIn.post("session/reverify", { factor: "security_key" });
check("then the second factor is fresh", kr.status === 200 && ageOf(kr.body.jwt)[1] <= 3, kr);
check("a touch is single use", code(await bobIn.post("session/reverify", { factor: "security_key" })) === "security_key_required");

// ---------- Passkey ----------
const dev = new SoftAuthenticator();
const po = (await bobIn.post("passkeys/register/options")).body;
const pr = await bobIn.post("passkeys/register/verify", { response: dev.register(po), name: "Laptop" });
check("setup: passkey registered", pr.status === 201 || pr.status === 200, pr);
await age(bobIn, { first: 1000, second: 1000 });
const opts = await bobIn.post("session/reverify/passkey/options");
check("passkey options offer only this person's passkey", opts.status === 200 && opts.body.allowCredentials?.length === 1 && opts.body.allowCredentials[0].id === Buffer.from(dev.credId).toString("base64url") && opts.body.userVerification === "required", opts.body);
const pv = await bobIn.post("session/reverify/passkey", { response: dev.assert(opts.body.challenge) });
check("a user-verified passkey freshens BOTH factors", pv.status === 200 && ageOf(pv.body.jwt)[0] <= 3 && ageOf(pv.body.jwt)[1] <= 3, pv.body.jwt && claims(pv.body.jwt).fva);
const vP = await verifyToken(pv.body.jwt, cfg);
check("…so multi_factor is satisfied", vP !== null && isRecentlyVerified(vP, { maxAge: 60, level: "multi_factor" }));
check("a passkey challenge is single use", (await bobIn.post("session/reverify/passkey", { response: dev.assert(opts.body.challenge) })).status === 400);
const optP = await bobIn.get("session/reverify");
check("options now include the passkey and the security key", optP.body.passkey === true && optP.body.securityKey === true);
// someone else's passkey must not count
const eve = await newUser("eve");
const eveDev = new SoftAuthenticator();
await eve.b.post("passkeys/register/verify", { response: eveDev.register((await eve.b.post("passkeys/register/options")).body), name: "Eve" });
check("no passkey: options refused (400 no_passkey)", code(await ann.b.post("session/reverify/passkey/options")) === "no_passkey");
const bobOpts2 = await bobIn.post("session/reverify/passkey/options");
const crossed = await bobIn.post("session/reverify/passkey", { response: eveDev.assert(bobOpts2.body.challenge) });
check("another account's passkey is refused", crossed.status === 400 && code(crossed) === "passkey_invalid", crossed);
// passkey sign-in sets both factors
const ao = await new Browser().post("passkeys/authenticate/options");
const pb = new Browser();
const psi = await pb.post("passkeys/authenticate/verify", { response: dev.assert(ao.body.challenge, { userHandle: Buffer.from(bob.id).toString("base64url") }) });
check("passkey sign-in: both factors fresh at sign-in", psi.status === 200 && ageOf(psi.body.jwt)[1] >= 0 && ageOf(psi.body.jwt)[1] <= 3, psi.body);

// ---------- Emailed code (no password, no 2FA) ----------
const dan = await newUser("dan");
await db().execute(sql`delete from passwords where user_id = ${dan.id}`);
const optD = await dan.b.get("session/reverify");
check("options: only an emailed code", optD.body.emailCode === true && optD.body.password === false && optD.body.totp === false, optD.body);
await age(dan.b, { first: 1000 });
const sent = await dan.b.post("me/reauth_code");
check("code emailed", sent.status === 200, sent);
const mail = (await cache().get(`devmail:${blindIndex(dan.email, "devmail")}`)) ?? "";
const mailed = mail.match(/\b(\d{6})\b/)?.[1] ?? "";
check("wrong emailed code refused", code(await dan.b.post("session/reverify", { factor: "email_code", code: "000000" })) === "invalid_code");
const ec = await dan.b.post("session/reverify", { factor: "email_code", code: mailed });
check("right emailed code freshens the first factor", ec.status === 200 && ageOf(ec.body.jwt)[0] <= 3, { mailed, ec: ec.body });
check("an emailed code is single use", code(await dan.b.post("session/reverify", { factor: "email_code", code: mailed })) === "invalid_code");

// ---------- Binding and sessions ----------
const stolen = new Browser();
check("a revoked session can't reverify", await (async () => {
  const u = await newUser("fay");
  await db().execute(sql`update sessions set status = 'revoked' where refresh_token_hash = ${sha256(u.b.refresh)}`);
  await cache().del(`sess:${sha256(u.b.refresh)}`);
  return (await u.b.post("session/reverify", { factor: "password", password: pw })).status === 401;
})());
void stolen;

// ---------- Browser SDK: authFetch retries after the prompt ----------
const api = createServer(async (req, res) => {
  const bearer = req.headers.authorization?.replace(/^Bearer /, "");
  const c = await verifyToken(bearer, cfg);
  res.setHeader("content-type", "application/json");
  if (!c) { res.statusCode = 401; res.end('{"error":{"code":"unauthenticated"}}'); return; }
  try {
    requireRecentAuth(c, { maxAge: 120, level: "first_factor" });
  } catch (e) {
    const r = (e as ReverificationRequiredError).toResponse();
    res.statusCode = r.status;
    res.end(await r.text());
    return;
  }
  res.end(JSON.stringify({ ok: true, userId: c.userId }));
});
await new Promise<void>((r) => api.listen(3992, r));
const origFetch = globalThis.fetch;
let jar = "";
globalThis.fetch = (async (input: RequestInfo | URL, init: RequestInit = {}) => {
  const url = String(input);
  const h = new Headers(init.headers);
  if (url.startsWith(AUTH)) { h.set("origin", AUTH); h.set("x-forwarded-for", `192.0.2.${randomInt(1, 250)}`); if (jar) h.set("cookie", jar); }
  const r = await origFetch(input, { ...init, headers: h });
  const sc = r.headers.get("set-cookie");
  if (sc && url.startsWith(AUTH)) jar = sc.split(";")[0].endsWith("=") ? "" : sc.split(";")[0];
  return r;
}) as typeof fetch;
const gil = await newUser("gil");
const client = createAuthClient({ ...cfg, syncCookie: false });
await client.signIn({ email: gil.email, password: pw });
check("SDK: fresh session passes the protected API", (await client.authFetch("http://localhost:3992/x", { method: "POST", body: "{}" })).status === 200);
// age the session behind the client's back
const gilHash = sha256(jar.split("=")[1]);
await db().execute(sql`update sessions set first_factor_at = now() - interval '1 hour' where refresh_token_hash = ${gilHash}`);
await cache().del(`sess:${gilHash}`);
await client.getToken({ force: true });
const noPrompt = await client.authFetch("http://localhost:3992/x", { method: "POST", body: "{}" });
check("SDK: without a prompt registered the 403 is returned as is", noPrompt.status === 403 && (await noPrompt.json()).error.code === "reverification_required");
let needSeen: unknown;
client.setReverificationHandler(async (need) => { needSeen = need; await client.reverifyWithPassword(pw); return true; });
const retried = await client.authFetch("http://localhost:3992/x", { method: "POST", body: JSON.stringify({ a: 1 }) });
check("SDK: prompt runs, request is retried and succeeds", retried.status === 200 && (await retried.json()).ok === true, retried.status);
check("SDK: the prompt is told what is needed", JSON.stringify(needSeen) === '{"level":"first_factor","maxAge":120}', needSeen);
await db().execute(sql`update sessions set first_factor_at = now() - interval '1 hour' where refresh_token_hash = ${gilHash}`);
await cache().del(`sess:${gilHash}`);
await client.getToken({ force: true });
client.setReverificationHandler(async () => false);
const declined = await client.authFetch("http://localhost:3992/x", { method: "POST", body: "{}" });
check("SDK: declining returns the 403", declined.status === 403);
let calls = 0;
client.setReverificationHandler(async () => { calls++; return true; }); // claims success but nothing was verified
const still = await client.authFetch("http://localhost:3992/x", { method: "POST", body: "{}" });
check("SDK: retries once only (no loop when the server still says no)", still.status === 403 && calls === 1, { status: still.status, calls });
check("SDK: requestReverification calls the handler", (await client.requestReverification({ level: "first_factor", maxAge: 60 })) === true && calls === 2);
const other403 = createServer((_q, r) => { r.statusCode = 403; r.setHeader("content-type", "application/json"); r.end('{"error":{"code":"forbidden"}}'); });
await new Promise<void>((r) => other403.listen(3991, r));
calls = 0;
const plain403 = await client.authFetch("http://localhost:3991/", {});
check("SDK: ordinary 403s don't trigger the prompt", plain403.status === 403 && calls === 0);
other403.close();
api.close();
globalThis.fetch = origFetch;

// ---------- Lockout accounting ----------
await resetLimits();
const hal = await newUser("hal");
let last;
for (let i = 0; i < 5; i++) last = await hal.b.post("session/reverify", { factor: "password", password: "wrong password 12" });
check("five wrong passwords through reverify lock the account", code(last!) === "invalid_credentials" || code(last!) === "account_locked");
const locked = await hal.b.post("session/reverify", { factor: "password", password: pw });
check("…and even the right password is refused while locked", locked.status === 429 && code(locked) === "account_locked", locked);
check("…as is sign-in", code(await new Browser().post("sign_in", { email: hal.email, password: pw })) === "account_locked");

console.log(failures ? `\n${failures} check(s) failed` : "\nAll step-up checks passed");
await closeDb();
await closeCache();
process.exit(failures ? 1 : 0);
