/** Passwordless sign-in by email code and magic link. Needs the service on :3000 with MAIL_TRANSPORT=dev. */
import { sql } from "drizzle-orm";
import { seedInstance } from "./seed";
import { cache, closeCache } from "../src/lib/cache";
import { blindIndex } from "../src/lib/crypto";
import { db, closeDb } from "../src/lib/db";
import { invalidateInstance, getInstance } from "../src/lib/auth/instance";
import { startTotpEnrollment } from "../src/lib/auth/mfa";
import { listAudit } from "../src/lib/audit";

const BASE = "http://localhost:3000";
let failures = 0;
const check = (name: string, ok: boolean, detail?: unknown) => {
  console.log(`${ok ? "✓" : "✗"} ${name}${ok ? "" : ` — ${JSON.stringify(detail)?.slice(0, 300)}`}`);
  if (!ok) failures++;
};
const settle = () => new Promise((r) => setTimeout(r, 400));

const seed = await seedInstance("Email code E2E", ["https://app.example.com"]);
const other = await seedInstance("Email code E2E (other)", []);
const setEnabled = async (instanceId: string, on: boolean) => {
  await db().execute(sql`update instances set settings = settings || ${JSON.stringify({ emailCodeSignIn: on })}::jsonb where id = ${instanceId}`);
  await invalidateInstance(instanceId);
};
const mailKey = (to: string) => `devmail:${blindIndex(to, "devmail")}`;
const readMail = async (to: string) => {
  const t = await cache().get(mailKey(to));
  if (!t) return null;
  const link = t.match(/https?:\/\/\S+\/magic-link\?\S+/)?.[0] ?? "";
  return { text: t, code: t.match(/\b(\d{6})\b/)?.[1] ?? "", link, token: decodeURIComponent(link.split("#token=")[1] ?? "") };
};
// Also resets the per-address send limit (5 an hour), which this test would otherwise hit on purpose-less repeats.
const clearMail = (to: string) => cache().del(mailKey(to), `rl:${seed.instanceId}:esi_send:${blindIndex(to, `email:${seed.instanceId}`)}`);

function jar(pk = seed.publishableKey) {
  let cookie = "";
  return {
    get cookie() { return cookie; },
    async call(path: string, body?: unknown, method = "POST") {
      const res = await fetch(`${BASE}/v1/client/${path}`, {
        method,
        headers: { "content-type": "application/json", "x-publishable-key": pk, origin: BASE, "x-forwarded-for": `203.0.113.${Math.floor(Math.random() * 250) + 1}`, ...(cookie ? { cookie } : {}) },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
      for (const c of res.headers.getSetCookie()) if (/^__dw_(r|2fa)/.test(c) && !/Max-Age=0/i.test(c)) cookie = c.split(";")[0];
      return { status: res.status, body: await res.json().catch(() => null) };
    },
  };
}

const email = `esi.${Date.now()}@example.com`;
const signup = jar();
const su = await signup.call("sign_up", { email, password: "a long enough password" });
const userId = su.body.user.id;
await clearMail(email);

// ----- Off by default -----
const a = jar();
check("off by default: environment says so", (await a.call("environment", undefined, "GET")).body.emailCodeSignIn === false);
const off = await a.call("sign_in/email_code", { email });
check("off by default: sending is refused", off.status === 400 && off.body.error.code === "email_code_disabled", off);
check("…and nothing is emailed", (await readMail(email)) === null);

await setEnabled(seed.instanceId, true);
check("turned on: environment says so", (await a.call("environment", undefined, "GET")).body.emailCodeSignIn === true);

// ----- No account enumeration -----
const ghost = `nobody.${Date.now()}@example.com`;
const g = await a.call("sign_in/email_code", { email: ghost });
check("unknown email gets the same answer as a real one", g.status === 200 && g.body.status === "sent");
check("…and no email is sent to it", (await readMail(ghost)) === null);

// ----- Code -----
const s1 = await a.call("sign_in/email_code", { email });
check("real email → sent", s1.status === 200 && s1.body.status === "sent");
const m1 = await readMail(email);
check("email has a 6-digit code and a sign-in link", !!m1 && /^\d{6}$/.test(m1.code) && m1.token.length >= 40, m1?.text);
check("link points at the hosted page with the token in the fragment", !!m1 && m1.link.includes(`/magic-link?pk=${encodeURIComponent(seed.publishableKey)}#token=`));
const stored = JSON.stringify(await cache().hgetall(`esi:${seed.instanceId}:${blindIndex(email, `email:${seed.instanceId}`)}`));
check("Valkey holds neither the code nor the link token in plaintext", !stored.includes(m1!.code) && !stored.includes(m1!.token) && stored.length > 10, stored);

const wrongCode = String((Number(m1!.code) + 1) % 1_000_000).padStart(6, "0");
const bad = await a.call("sign_in/email_code/verify", { email, code: wrongCode });
check("wrong code → 400", bad.status === 400 && bad.body.error.code === "invalid_code");
const ok = await a.call("sign_in/email_code/verify", { email, code: m1!.code });
check("right code → signed in with a token and refresh cookie", ok.status === 200 && ok.body.status === "complete" && ok.body.user.id === userId && !!ok.body.jwt && a.cookie.startsWith("__dw_r"), ok.body);
check("signing in by email marks the address verified", ok.body.user.emailAddresses[0].verified === true);
check("the session works", (await a.call("session", undefined, "GET")).body.user?.id === userId);
check("the code works only once", (await jar().call("sign_in/email_code/verify", { email, code: m1!.code })).status === 400);
check("using the code burns the link from the same email", (await jar().call("sign_in/magic_link", { token: m1!.token })).status === 400);
await settle();
const audit = (await listAudit(seed.instanceId, { target: userId, limit: 50 })).data;
check("audit: sign-in recorded with method email_code", audit.some((e) => e.type === "user.signed_in" && e.data?.method === "email_code"));
check("audit: wrong code recorded", audit.some((e) => e.type === "user.sign_in_failed" && e.data?.reason === "wrong_email_code"));

// ----- Magic link -----
await clearMail(email);
const b = jar();
await b.call("sign_in/email_code", { email, redirectUrl: "https://app.example.com/after" });
const m2 = (await readMail(email))!;
const wrongInst = await jar(other.publishableKey).call("sign_in/magic_link", { token: m2.token });
check("a link can't be used against another instance", wrongInst.status === 400);
const ml = await b.call("sign_in/magic_link", { token: m2.token });
check("link → signed in, and returns the allowed redirect", ml.status === 200 && ml.body.status === "complete" && ml.body.redirectUrl === "https://app.example.com/after", ml.body);
check("the link works only once", (await jar().call("sign_in/magic_link", { token: m2.token })).status === 400);
check("using the link burns the code from the same email", (await jar().call("sign_in/email_code/verify", { email, code: m2.code })).status === 400);
check("a garbage token → 400", (await jar().call("sign_in/magic_link", { token: "x".repeat(43) })).status === 400);

await clearMail(email);
await jar().call("sign_in/email_code", { email, redirectUrl: "https://evil.example.net/steal" });
const m3 = (await readMail(email))!;
const ml3 = await jar().call("sign_in/magic_link", { token: m3.token });
check("a redirect outside the allowed origins is dropped", ml3.status === 200 && ml3.body.redirectUrl === null, ml3.body);

// ----- A newer email replaces the older one -----
await clearMail(email);
await jar().call("sign_in/email_code", { email });
const old = (await readMail(email))!;
await clearMail(email);
await jar().call("sign_in/email_code", { email });
const fresh = (await readMail(email))!;
check("an older link stops working once a new email is sent", (await jar().call("sign_in/magic_link", { token: old.token })).status === 400);
check("an older code stops working once a new email is sent", old.code === fresh.code || (await jar().call("sign_in/email_code/verify", { email, code: old.code })).status === 400);

// ----- 5 wrong guesses burn the code -----
const guesser = jar();
const wrong = String((Number(fresh.code) + 1) % 1_000_000).padStart(6, "0");
for (let i = 0; i < 5; i++) await guesser.call("sign_in/email_code/verify", { email, code: wrong });
check("after 5 wrong guesses even the right code fails", (await guesser.call("sign_in/email_code/verify", { email, code: fresh.code })).status === 400);
check("…and the link from that email is burned too", (await jar().call("sign_in/magic_link", { token: fresh.token })).status === 400);

// ----- Simultaneous use: only one wins -----
await clearMail(email);
await jar().call("sign_in/email_code", { email });
const race = (await readMail(email))!;
const [r1, r2] = await Promise.all([jar().call("sign_in/email_code/verify", { email, code: race.code }), jar().call("sign_in/magic_link", { token: race.token })]);
check("code and link used at the same moment: exactly one signs in", [r1.status, r2.status].filter((s) => s === 200).length === 1, [r1.status, r2.status]);

// ----- Two-factor still applies -----
const inst = (await getInstance(seed.instanceId))!;
await startTotpEnrollment(inst, userId, email);
await db().execute(sql`update mfa_totp set verified_at = now() where user_id = ${userId}`);
await clearMail(email);
const c = jar();
await c.call("sign_in/email_code", { email });
const m4 = (await readMail(email))!;
const tf = await c.call("sign_in/email_code/verify", { email, code: m4.code });
check("2FA account → needs_second_factor, no session yet", tf.status === 200 && tf.body.status === "needs_second_factor" && !tf.body.jwt && c.cookie.startsWith("__dw_2fa"), tf.body);
await clearMail(email);
await jar().call("sign_in/email_code", { email });
const m5 = (await readMail(email))!;
const tf2 = await jar().call("sign_in/magic_link", { token: m5.token });
check("2FA account via link → needs_second_factor too", tf2.body.status === "needs_second_factor" && !tf2.body.jwt);
await db().execute(sql`delete from mfa_totp where user_id = ${userId}`);

// ----- Suspended users can't get in -----
await db().execute(sql`update users set banned = true where id = ${userId}`);
await clearMail(email);
await jar().call("sign_in/email_code", { email });
const m6 = (await readMail(email))!;
const ban = await jar().call("sign_in/email_code/verify", { email, code: m6.code });
check("suspended account → 403, no session", ban.status === 403 && !ban.body.jwt);
await db().execute(sql`update users set banned = false where id = ${userId}`);

// ----- Per-address send limit (silent) -----
const flood = `flood.${Date.now()}@example.com`;
await jar().call("sign_up", { email: flood, password: "a long enough password" });
await clearMail(flood);
for (let i = 0; i < 5; i++) await jar().call("sign_in/email_code", { email: flood });
await cache().del(mailKey(flood));
const sixth = await jar().call("sign_in/email_code", { email: flood });
check("6th email in an hour: same answer, but nothing is sent", sixth.status === 200 && (await readMail(flood)) === null);

// ----- Turning it off stops it -----
await setEnabled(seed.instanceId, false);
check("turned off again: verify is refused too", (await jar().call("sign_in/email_code/verify", { email, code: "123456" })).body.error?.code === "email_code_disabled");

// ----- Hosted pages -----
await setEnabled(seed.instanceId, true);
const page = await fetch(`${BASE}/magic-link?pk=${encodeURIComponent(seed.publishableKey)}`);
const html = await page.text();
check("magic-link page renders under the strict nonce CSP", page.status === 200 && /script-src [^;]*'nonce-[^;]*'strict-dynamic'/.test(page.headers.get("content-security-policy") ?? ""));
check("magic-link page sends no referrer", /no-referrer/.test(html));
const signin = await (await fetch(`${BASE}/sign-in?pk=${encodeURIComponent(seed.publishableKey)}`)).text();
check("sign-in page offers the email code option when it's on", signin.includes("Email me a sign-in code instead"));
const signinOff = await (await fetch(`${BASE}/sign-in?pk=${encodeURIComponent(other.publishableKey)}`)).text();
check("…and hides it when it's off", !signinOff.includes("Email me a sign-in code instead"));

await closeDb();
await closeCache();
console.log(failures ? `\n${failures} check(s) failed` : "\nAll email code and magic link checks passed");
process.exit(failures ? 1 : 0);
