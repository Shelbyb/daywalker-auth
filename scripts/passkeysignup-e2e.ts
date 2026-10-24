/**
 * Passkey-first sign-up: email code, then a passkey creates the account (no password, email verified).
 * Uses the software authenticator. Needs the service on :3000 with MAIL_TRANSPORT=dev (RP ID "localhost").
 */
import { sql } from "drizzle-orm";
import { seedInstance } from "./seed";
import { SoftAuthenticator, AUTH } from "./soft-authenticator";
import { db, closeDb } from "../src/lib/db";
import { cache, closeCache } from "../src/lib/cache";
import { blindIndex } from "../src/lib/crypto";
import { invalidateInstance } from "../src/lib/auth/instance";

let failures = 0;
const check = (name: string, ok: boolean, detail?: unknown) => {
  console.log(`${ok ? "✓" : "✗"} ${name}${ok ? "" : ` — ${JSON.stringify(detail)?.slice(0, 400)}`}`);
  if (!ok) failures++;
};
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const rows = async (q: ReturnType<typeof sql>) => (await db().execute(q)) as unknown as Record<string, any>[];
const settle = () => new Promise((r) => setTimeout(r, 500));

const A = await seedInstance("Passkey signup E2E", []);
const B = await seedInstance("Passkey signup E2E other", []);
const setSettings = async (id: string, s: Record<string, unknown>) => {
  await db().execute(sql`update instances set settings = settings || ${JSON.stringify(s)}::jsonb where id = ${id}`);
  await invalidateInstance(id);
};
const mailKey = (to: string) => `devmail:${blindIndex(to, "devmail")}`;
const sendKey = (inst: string, to: string) => `rl:${inst}:pks_send:${blindIndex(to, `email:${inst}`)}`;
const mailCode = async (to: string) => (await cache().get(mailKey(to)))?.match(/\b(\d{6})\b/)?.[1] ?? "";
let n = 0;

class Browser {
  cookies = new Map<string, string>();
  constructor(public key = A.publishableKey) {}
  async call(method: string, path: string, body?: unknown) {
    const res = await fetch(`${AUTH}/v1/client/${path}`, {
      method,
      headers: { "content-type": "application/json", "x-publishable-key": this.key, origin: AUTH, "x-forwarded-for": `203.0.113.${(++n % 250) + 1}`, cookie: [...this.cookies].map(([k, v]) => `${k}=${v}`).join("; ") },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    for (const c of res.headers.getSetCookie()) {
      const kv = c.split(";")[0];
      const k = kv.slice(0, kv.indexOf("=")), v = kv.slice(kv.indexOf("=") + 1);
      if (/max-age=0/i.test(c) || !v) this.cookies.delete(k);
      else this.cookies.set(k, v);
    }
    return { status: res.status, body: await res.json().catch(() => null) };
  }
  post = (p: string, b?: unknown) => this.call("POST", p, b);
  get = (p: string) => this.call("GET", p);
}
const code = (r: { body: { error?: { code?: string } } | null }) => r.body?.error?.code;
const stamp = Date.now();
const start = (b: Browser, email: string, extra: Record<string, unknown> = {}) => b.post("sign_up/passkey/start", { email, firstName: "Grace", lastName: "Hopper", ...extra });

// ---------- Off by default ----------
check("environment: off by default", (await new Browser().get("environment")).body.passkeySignUp === false);
const off = await start(new Browser(), `off.${stamp}@example.com`);
check("start refused while off", off.status === 400 && code(off) === "passkey_signup_disabled", off);
check("verify and complete refused while off", code(await new Browser().post("sign_up/passkey/verify", { email: `off.${stamp}@example.com`, code: "123456" })) === "passkey_signup_disabled" &&
  code(await new Browser().post("sign_up/passkey/complete", { token: "x".repeat(40), response: { id: "a", rawId: "a", type: "public-key", response: {} } })) === "passkey_signup_disabled");

await setSettings(A.instanceId, { passkeySignUp: true });
check("environment: on when enabled", (await new Browser().get("environment")).body.passkeySignUp === true);

// ---------- Happy path ----------
const email = `Grace.${stamp}@Example.com`; // mixed case on purpose
const lower = email.toLowerCase();
const b = new Browser();
const s1 = await start(b, email);
check("start: 200, nothing created", s1.status === 200 && s1.body.sent === true, s1);
check("nothing exists yet", (await rows(sql`select 1 from users where instance_id = ${A.instanceId}`)).length === 0);
const c1 = await mailCode(lower);
check("a 6-digit code was emailed", /^\d{6}$/.test(c1), c1);
check("only a hash of the code and an encrypted profile are held", !(JSON.stringify(await cache().hgetall(`code:passkey_signup:${A.instanceId}:${blindIndex(lower, `email:${A.instanceId}`)}`))).includes(c1));

const wrong = await b.post("sign_up/passkey/verify", { email, code: c1 === "000000" ? "000001" : "000000" });
check("wrong code rejected", wrong.status === 400 && code(wrong) === "invalid_code", wrong);
check("bad code format rejected", (await b.post("sign_up/passkey/verify", { email, code: "abc" })).status === 400);
const v = await b.post("sign_up/passkey/verify", { email, code: c1 });
check("right code gives a token and passkey options", v.status === 200 && typeof v.body.token === "string" && v.body.token.length >= 40 && v.body.options?.challenge, v.body);
const opts = v.body.options;
check("options: RP, discoverable credential, user verification required, no attestation",
  opts.rp?.id === "localhost" && opts.authenticatorSelection?.residentKey === "required" && opts.authenticatorSelection?.userVerification === "required" && opts.attestation === "none" && opts.user?.name === lower, opts);
const newUserId = Buffer.from(opts.user.id, "base64url").toString();
check("the user handle is a fresh user ID", /^user_/.test(newUserId));
check("still nothing created after the code", (await rows(sql`select 1 from users where instance_id = ${A.instanceId}`)).length === 0);
check("the code is single-use", code(await b.post("sign_up/passkey/verify", { email, code: c1 })) === "invalid_code");

// Failed attempts at the final step
const dev = new SoftAuthenticator(true);
const bad1 = await b.post("sign_up/passkey/complete", { token: v.body.token, response: dev.register(opts, { origin: "https://evil.example" }) });
check("wrong origin rejected", bad1.status === 400 && code(bad1) === "passkey_invalid", bad1);
check("…and that burned the token (single use)", code(await b.post("sign_up/passkey/complete", { token: v.body.token, response: dev.register(opts) })) === "challenge_expired");
check("still nothing created", (await rows(sql`select 1 from users where instance_id = ${A.instanceId}`)).length === 0);

// A second go, covering challenge and UV failures
await cache().del(sendKey(A.instanceId, lower));
await start(b, email);
const v2 = await b.post("sign_up/passkey/verify", { email, code: await mailCode(lower) });
check("second code works", v2.status === 200, v2.body);
const bad2 = await b.post("sign_up/passkey/complete", { token: v2.body.token, response: dev.register(v2.body.options, { challenge: v.body.options.challenge }) });
check("another challenge rejected", code(bad2) === "passkey_invalid", bad2);
await cache().del(sendKey(A.instanceId, lower));
await start(b, email);
const v3 = await b.post("sign_up/passkey/verify", { email, code: await mailCode(lower) });
const bad3 = await b.post("sign_up/passkey/complete", { token: v3.body.token, response: dev.register(v3.body.options, { uv: false }) });
check("a passkey without user verification rejected", code(bad3) === "passkey_invalid", bad3);

// The real thing
await cache().del(sendKey(A.instanceId, lower));
await start(b, email);
const v4 = await b.post("sign_up/passkey/verify", { email, code: await mailCode(lower) });
const device = new SoftAuthenticator(true);
const done = await b.post("sign_up/passkey/complete", { token: v4.body.token, name: "Grace's laptop", response: device.register(v4.body.options) });
check("account created: 201 with user, session and token", done.status === 201 && done.body.user?.id && done.body.sessionId && typeof done.body.jwt === "string", done.body);
check("email is verified from the start", done.body.user.emailAddresses[0].email === lower && done.body.user.emailAddresses[0].verified === true && done.body.user.firstName === "Grace", done.body.user);
check("signed in with a refresh cookie", [...b.cookies.keys()].some((k) => k.startsWith("__dw_rt_")));
const uid = done.body.user.id;
check("no password row", (await rows(sql`select 1 from passwords where user_id = ${uid}`)).length === 0);
const pk = await rows(sql`select name, instance_id, backed_up from passkeys where user_id = ${uid}`);
check("one passkey, named, in the right instance", pk.length === 1 && pk[0].name === "Grace's laptop" && pk[0].instance_id === A.instanceId && pk[0].backed_up === true, pk);
const sess = await rows(sql`select first_factor_at, second_factor_at from sessions where user_id = ${uid}`);
check("the session counts as fully verified (passkey = two factors)", sess.length === 1 && sess[0].first_factor_at && sess[0].second_factor_at, sess);
await settle();
const audit = await rows(sql`select count(*)::int c from audit_events where instance_id = ${A.instanceId} and type = 'user.signed_up' and target_id = ${uid}`);
check("sign-up audited", audit[0].c === 1, audit);
check("the stored email is encrypted", !JSON.stringify(await rows(sql`select email_enc from email_addresses where user_id = ${uid}`)).includes("Hopper") && !JSON.stringify(await rows(sql`select email_enc from email_addresses where user_id = ${uid}`)).includes(lower));
check("token can't be replayed", code(await b.post("sign_up/passkey/complete", { token: v4.body.token, response: device.register(v4.body.options) })) === "challenge_expired");

// ---------- It works as a login ----------
const me = await b.post("session/token");
check("session works", me.status === 200 && me.body.userId === uid, me.body);
const fresh = new Browser();
const ao = (await fresh.post("passkeys/authenticate/options")).body;
const signedIn = await fresh.post("passkeys/authenticate/verify", { response: device.assert(ao.challenge) });
check("signing in with the new passkey works", signedIn.status === 200 && signedIn.body.user?.id === uid, signedIn.body);
const pw = await new Browser().post("sign_in", { email: lower, password: "anything at all 123" });
check("password sign-in fails (there is none)", pw.status === 400 && code(pw) === "invalid_credentials", pw);
const reset = await new Browser().post("sign_up", { email: lower, password: "a long enough password" });
check("password sign-up with the same email is refused", reset.status === 409 && code(reset) === "email_taken", reset);

// ---------- Existing addresses reveal nothing ----------
await cache().del(mailKey(lower), sendKey(A.instanceId, lower));
const dup = await start(new Browser(), lower);
check("existing account: same answer, no email", dup.status === 200 && dup.body.sent === true && (await mailCode(lower)) === "", dup);
const dupV = await new Browser().post("sign_up/passkey/verify", { email: lower, code: "123456" });
check("…and there is nothing to verify", code(dupV) === "invalid_code", dupV);

// ---------- Rules apply ----------
await setSettings(A.instanceId, { signUpBlockedDomains: ["blocked.example"] });
const blocked = await start(new Browser(), `x.${stamp}@blocked.example`);
check("blocked domain refused", blocked.status === 403 && code(blocked) === "sign_up_not_allowed", blocked);
await setSettings(A.instanceId, { signUpBlockedDomains: [], signUpAllowedDomains: ["only.example"] });
check("allow-list enforced", code(await start(new Browser(), `x.${stamp}@example.com`)) === "sign_up_not_allowed");
await setSettings(A.instanceId, { signUpAllowedDomains: [] });

await db().execute(sql`update instances set legal = ${JSON.stringify({ required: true, termsUrl: "https://example.com/terms", privacyUrl: null, version: "v1" })}::jsonb where id = ${A.instanceId}`);
await invalidateInstance(A.instanceId);
const legalEmail = `legal.${stamp}@example.com`;
check("terms required", code(await start(new Browser(), legalEmail)) === "legal_required");
const lb = new Browser();
await start(lb, legalEmail, { legalAccepted: true });
const lv = await lb.post("sign_up/passkey/verify", { email: legalEmail, code: await mailCode(legalEmail) });
const ld = await lb.post("sign_up/passkey/complete", { token: lv.body.token, response: new SoftAuthenticator().register(lv.body.options) });
const acc = await rows(sql`select method, version from legal_acceptances where user_id = ${ld.body.user?.id ?? ""}`);
check("acceptance recorded with the method", ld.status === 201 && acc.length === 1 && acc[0].method === "passkey" && acc[0].version === "v1", { ld: ld.body, acc });
await db().execute(sql`update instances set legal = null where id = ${A.instanceId}`).catch(() => undefined);
await db().execute(sql`update instances set legal = ${JSON.stringify({ required: false, termsUrl: null, privacyUrl: null, version: "v1" })}::jsonb where id = ${A.instanceId}`);
await invalidateInstance(A.instanceId);

// ---------- Races and isolation ----------
const raceEmail = `race.${stamp}@example.com`;
const rb = new Browser();
await start(rb, raceEmail);
const rv = await rb.post("sign_up/passkey/verify", { email: raceEmail, code: await mailCode(raceEmail) });
const taken = await new Browser().post("sign_up", { email: raceEmail, password: "a long enough password" });
const rc = await rb.post("sign_up/passkey/complete", { token: rv.body.token, response: new SoftAuthenticator().register(rv.body.options) });
check("address taken in between: 409, nothing half-created", taken.status === 201 && rc.status === 409 && code(rc) === "email_taken" &&
  (await rows(sql`select 1 from users where id = ${Buffer.from(rv.body.options.user.id, "base64url").toString()}`)).length === 0 &&
  (await rows(sql`select 1 from passkeys where instance_id = ${A.instanceId} and user_id = ${Buffer.from(rv.body.options.user.id, "base64url").toString()}`)).length === 0, rc.body);

await setSettings(B.instanceId, { passkeySignUp: true });
const iso = `iso.${stamp}@example.com`;
const ib = new Browser();
await start(ib, iso);
const iv = await ib.post("sign_up/passkey/verify", { email: iso, code: await mailCode(iso) });
const other = new Browser(B.publishableKey);
const cross = await other.post("sign_up/passkey/complete", { token: iv.body.token, response: new SoftAuthenticator().register(iv.body.options) });
check("a token from one app is useless in another", cross.status === 400 && code(cross) === "challenge_expired", cross);
check("…and wasted", code(await ib.post("sign_up/passkey/complete", { token: iv.body.token, response: new SoftAuthenticator().register(iv.body.options) })) === "challenge_expired");
const otherSame = await start(new Browser(B.publishableKey), iso);
check("the same address in another app is independent", otherSame.status === 200, otherSame);

// Brute force on the code
const bf = `bf.${stamp}@example.com`;
const bb = new Browser();
await start(bb, bf);
const real = await mailCode(bf);
const guess = real === "111111" ? "222222" : "111111";
for (let i = 0; i < 5; i++) await bb.post("sign_up/passkey/verify", { email: bf, code: guess });
check("five wrong guesses burn the code", code(await bb.post("sign_up/passkey/verify", { email: bf, code: real })) === "invalid_code");

// Send throttling is silent
const th = `th.${stamp}@example.com`;
await cache().del(sendKey(A.instanceId, th));
for (let i = 0; i < 5; i++) await start(new Browser(), th);
await cache().del(mailKey(th));
const sixth = await start(new Browser(), th);
check("sends are limited per address, silently", sixth.status === 200 && sixth.body.sent === true && (await mailCode(th)) === "", sixth);
const junk = [(await start(new Browser(), "not-an-email")).status, (await new Browser().post("sign_up/passkey/complete", { token: "short", response: {} })).status];
check("junk input is rejected", junk.every((c) => c >= 400 && c < 500), junk);

console.log(failures ? `\n${failures} check(s) failed` : "\nAll passkey sign-up checks passed");
await closeDb();
await closeCache();
process.exit(failures ? 1 : 0);
