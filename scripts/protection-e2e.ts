/**
 * Sign-up protection (email domain rules, throwaway addresses, Turnstile human check) and required
 * two-factor (app-wide with a grace period, and per organization).
 * Needs the service on :3000 started with TURNSTILE_TEST_BASE_URL=http://localhost:3993 (a mock is started here).
 */
import { createServer, type Server } from "node:http";
import { randomInt } from "node:crypto";
import { sql } from "drizzle-orm";
import { seedInstance } from "./seed";
import { db, closeDb } from "../src/lib/db";
import { closeCache } from "../src/lib/cache";
import { listAudit } from "../src/lib/audit";
import { totpAt, currentCounter } from "../src/lib/auth/totp";

const AUTH = "http://localhost:3000";
let failures = 0;
const check = (name: string, ok: boolean, detail?: unknown) => {
  console.log(`${ok ? "✓" : "✗"} ${name}${ok ? "" : ` — ${JSON.stringify(detail)?.slice(0, 400)}`}`);
  if (!ok) failures++;
};

// ---------- Mock Turnstile ----------
const SECRET = "0x4AAAAAAAtest-secret-key";
const issued = new Set<string>();
let lastIp = "";
let turnstileUp = true;
const turnstile: Server = createServer(async (req, res) => {
  let raw = "";
  for await (const c of req) raw += c;
  const f = new URLSearchParams(raw);
  lastIp = f.get("remoteip") ?? "";
  const tok = f.get("response") ?? "";
  const ok = req.url === "/turnstile/v0/siteverify" && f.get("secret") === SECRET && issued.delete(tok); // single use, like Turnstile
  res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ success: ok }));
});
await new Promise<void>((r) => turnstile.listen(3993, r));
const newCaptcha = () => {
  const t = `tok-${Date.now()}-${randomInt(1e9)}`;
  issued.add(t);
  return t;
};

const seed = await seedInstance("Protection E2E", []);
const { publishableKey: pk, secretKey: sk, instanceId } = seed;
const api = (method: string, path: string, body?: unknown) =>
  fetch(`${AUTH}/v1/${path}`, { method, headers: { authorization: `Bearer ${sk}`, "content-type": "application/json" }, body: body === undefined ? undefined : JSON.stringify(body) });

class Browser {
  cookies = new Map<string, string>();
  ip = `198.51.100.${randomInt(1, 250)}`;
  async call(method: string, path: string, body?: unknown) {
    const r = await fetch(`${AUTH}/v1/client/${path}`, {
      method,
      headers: { "content-type": "application/json", "x-publishable-key": pk, origin: AUTH, "x-forwarded-for": this.ip, cookie: [...this.cookies].map(([k, v]) => `${k}=${v}`).join("; ") },
      body: body === undefined ? undefined : JSON.stringify(body),
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
}
const code = (r: { body: { error?: { code?: string } } | null }) => r.body?.error?.code;
const PW = "a long enough password";
const t = Date.now();
const signUp = (email: string, extra: Record<string, unknown> = {}) => new Browser().post("sign_up", { email, password: PW, ...extra });

// ---------- Email rules ----------
check("protection starts off", (await (await api("GET", "instance/protection")).json()).allowedDomains.length === 0);
check("a bad domain is refused", (await api("PATCH", "instance/protection", { allowedDomains: ["not a domain"] })).status >= 400);
check("unknown fields are refused", (await api("PATCH", "instance/protection", { surprise: true })).status >= 400);
check("needs the secret key", (await fetch(`${AUTH}/v1/instance/protection`)).status === 401);

const nobody = await signUp(`free.${t}@mailinator.com`);
check("throwaway addresses are allowed until blocked", nobody.status === 201);
await api("PATCH", "instance/protection", { blockDisposableEmails: true, blockedDomains: ["spam.example"] });
const disp = await signUp(`x.${t}@mailinator.com`);
check("a throwaway address is refused once blocked", disp.status === 403 && code(disp) === "sign_up_not_allowed", disp.body);
check("…including its subdomains", code(await signUp(`x.${t}@inbox.mailinator.com`)) === "sign_up_not_allowed");
check("a blocked domain is refused", code(await signUp(`x.${t}@spam.example`)) === "sign_up_not_allowed");
check("the same generic message either way", disp.body?.error?.message === (await signUp(`y.${t}@spam.example`)).body?.error?.message);
check("an ordinary address still works", (await signUp(`ok.${t}@example.com`)).status === 201);
check("an existing account at a now-blocked domain can still sign in", (await new Browser().post("sign_in", { email: `free.${t}@mailinator.com`, password: PW })).body?.status === "complete");

await api("PATCH", "instance/protection", { allowedDomains: ["acme.test"], blockedDomains: [], blockDisposableEmails: false });
check("with an allow-list, other domains are refused", code(await signUp(`z.${t}@example.com`)) === "sign_up_not_allowed");
check("…the listed domain works", (await signUp(`a.${t}@acme.test`)).status === 201);
check("…and its subdomains", (await signUp(`b.${t}@eu.acme.test`)).status === 201);
check("…but not a look-alike", code(await signUp(`c.${t}@notacme.test`)) === "sign_up_not_allowed");
await api("PATCH", "instance/protection", { allowedDomains: [] });

// ---------- Human check ----------
check("a site key without a secret is refused", (await api("PATCH", "instance/protection", { captcha: { siteKey: "0x4AAAAAAAsitekey" } })).status === 400);
const on = await (await api("PATCH", "instance/protection", { captcha: { siteKey: "0x4AAAAAAAsitekey", secretKey: SECRET } })).json();
check("turn the human check on", on.captcha?.siteKey === "0x4AAAAAAAsitekey" && on.captcha.secretSet === true, on);
check("the secret is never returned", !JSON.stringify(on).includes(SECRET) && !JSON.stringify(await (await api("GET", "instance/protection")).json()).includes(SECRET));
const stored = (await db().execute(sql`select captcha_secret_enc as s from instances where id = ${instanceId}`)) as unknown as { s: string }[];
check("…and stored encrypted", !!stored[0].s && !stored[0].s.includes(SECRET));
const env = (await new Browser().get("environment")).body;
check("the environment tells the browser to show the widget", env.captcha?.provider === "turnstile" && env.captcha.siteKey === "0x4AAAAAAAsitekey" && !JSON.stringify(env).includes(SECRET), env.captcha);

const noTok = await signUp(`h1.${t}@example.com`);
check("sign-up without an answer is refused", noTok.status === 400 && code(noTok) === "captcha_required", noTok.body);
check("a made-up answer is refused", code(await signUp(`h2.${t}@example.com`, { captchaToken: "made-up" })) === "captcha_failed");
const tok = newCaptcha();
const human = new Browser();
const hOk = await human.post("sign_up", { email: `h3.${t}@example.com`, password: PW, captchaToken: tok });
check("a real answer works", hOk.status === 201, hOk.body);
check("…and the person's IP is passed along", lastIp === human.ip, lastIp);
check("an answer can't be used twice", code(await signUp(`h4.${t}@example.com`, { captchaToken: tok })) === "captcha_failed");
await db().execute(sql`update instances set settings = settings || '{"emailCodeSignIn": true}'::jsonb where id = ${instanceId}`);
await api("PATCH", "instance/protection", {}); // refresh the cached instance (and must not undo the change above)
check("emailing a sign-in code needs it too", code(await new Browser().post("sign_in/email_code", { email: `h3.${t}@example.com` })) === "captcha_required");
check("…and works with an answer", (await new Browser().post("sign_in/email_code", { email: `h3.${t}@example.com`, captchaToken: newCaptcha() })).status === 200);
check("password sign-in doesn't need it", (await new Browser().post("sign_in", { email: `h3.${t}@example.com`, password: PW })).body?.status === "complete");
turnstileUp = false;
await new Promise<void>((r) => turnstile.close(() => r()));
check("if Turnstile can't be reached, sign-up is refused (fails closed)", code(await signUp(`h5.${t}@example.com`, { captchaToken: newCaptcha() })) === "captcha_failed");
void turnstileUp;
const off = await (await api("PATCH", "instance/protection", { captcha: null })).json();
check("turning it off", off.captcha === null && (await signUp(`h6.${t}@example.com`)).status === 201);

// ---------- Required two-factor (app-wide) ----------
const pat = async (email: string) => {
  const b = new Browser();
  const r = await b.post("sign_up", { email, password: PW });
  return { b, r, email };
};
const early = await pat(`early.${t}@example.com`);
const graced = await (await api("PATCH", "instance/protection", { requireTwoFactor: true, twoFactorGraceDays: 7 })).json();
check("require two-factor with a 7-day grace period", graced.requireTwoFactor === true && Date.parse(graced.twoFactorGraceUntil) > Date.now() + 6 * 86_400_000, graced);
const g1 = new Browser();
const gIn = await g1.post("sign_in", { email: early.email, password: PW });
check("during the grace period, sign-in still gets a token", gIn.body?.status === "complete" && !!gIn.body.jwt && !gIn.body.twoFactorSetupRequired, gIn.body);
const gSec = (await g1.get("me/security")).body;
check("…and the account page is told it's required", gSec.twoFactorRequired === true && !!gSec.twoFactorGraceUntil, gSec);

await api("PATCH", "instance/protection", { requireTwoFactor: true, twoFactorGraceDays: 0 });
const tokenOf = (b: Browser) => b.post("session/token");
const blocked = await tokenOf(early.b);
check("after the grace period, an existing session gets no new token", blocked.status === 403 && code(blocked) === "two_factor_setup_required", blocked.body);
const n1 = new Browser();
const nIn = await n1.post("sign_in", { email: early.email, password: PW });
check("signing in now: complete, but no token and a clear flag", nIn.status === 200 && nIn.body.status === "complete" && nIn.body.jwt === null && nIn.body.twoFactorSetupRequired === true, nIn.body);
check("…the session exists, so the account page works", (await n1.get("me/security")).status === 200);
const freshB = new Browser();
const fresh = await freshB.post("sign_up", { email: `new.${t}@example.com`, password: PW });
check("a brand-new account is in the same state", fresh.status === 201 && fresh.body.jwt === null && fresh.body.twoFactorSetupRequired === true, fresh.body);
const { secret } = (await n1.post("mfa/totp")).body;
const conf = await n1.post("mfa/totp/verify", { code: totpAt(secret, currentCounter()) });
check("they can turn on two-factor", conf.status === 200 && conf.body.backupCodes?.length === 10, conf.body);
const after = await tokenOf(n1);
check("…and tokens work straight away", after.status === 200 && !!after.body.jwt, after.body);
check("…on their other session too", (await tokenOf(early.b)).status === 200);
await api("PATCH", "instance/protection", { requireTwoFactor: false });
check("turning it off gives tokens back to everyone", (await tokenOf(freshB)).status === 200);

// ---------- Required two-factor (per organization) ----------
const admin = await pat(`orgadmin.${t}@example.com`);
const member = await pat(`member.${t}@example.com`);
const org = (await admin.b.post("organizations", { name: "Secure Co" })).body.organization;
await db().execute(sql`insert into memberships (org_id, user_id, role) values (${org.id}, ${member.r.body.user.id}, 'member')`);
check("member can make the organization active before it's required", (await member.b.post("session/active_org", { orgId: org.id })).status === 200);
const lock = await admin.b.call("PATCH", `organizations/${org.id}`, { requireTwoFactor: true });
check("an admin without two-factor can't require it (no self-lockout)", lock.status === 400 && code(lock) === "two_factor_required_first", lock.body);
const { secret: s2 } = (await admin.b.post("mfa/totp")).body;
await admin.b.post("mfa/totp/verify", { code: totpAt(s2, currentCounter()) });
const req2 = await admin.b.call("PATCH", `organizations/${org.id}`, { requireTwoFactor: true });
check("with two-factor on, the admin can require it", req2.status === 200);
check("a plain member can't change it", (await member.b.call("PATCH", `organizations/${org.id}`, { requireTwoFactor: false })).status === 403);
const claims = (jwt: string) => JSON.parse(Buffer.from(jwt.split(".")[1], "base64url").toString());
const mTok = await tokenOf(member.b);
check("a member without two-factor still gets a token, but without the organization", mTok.status === 200 && !claims(mTok.body.jwt).org_id, mTok.body.jwt && claims(mTok.body.jwt));
const sw = await member.b.post("session/active_org", { orgId: org.id });
check("…and can't make it active", sw.status === 403 && code(sw) === "two_factor_setup_required", sw.body);
const aTok = await admin.b.post("session/active_org", { orgId: org.id });
check("the admin (with two-factor) gets the organization claims", aTok.status === 200 && claims(aTok.body.jwt).org_id === org.id, aTok.body);
const list = (await member.b.get("organizations")).body.organizations;
check("the organization list says it's required", list.some((o: { id: string; requireTwoFactor: boolean }) => o.id === org.id && o.requireTwoFactor === true), list);
const be = await (await api("PATCH", `organizations/${org.id}`, { requireTwoFactor: false })).json();
check("the backend API can change it", be.requireTwoFactor === false && (await (await api("GET", `organizations/${org.id}`)).json()).requireTwoFactor === false);
check("…and the member can use the organization again", (await member.b.post("session/active_org", { orgId: org.id })).status === 200);

await new Promise((r) => setTimeout(r, 400));
const audit = (await listAudit(instanceId, { limit: 200 })).data;
check("audit log: protection changes, without the secret", audit.some((e) => e.type === "instance.settings_updated" && !!e.data?.protection) && !JSON.stringify(audit).includes(SECRET));

await closeDb();
await closeCache();
console.log(failures ? `\n${failures} check(s) failed` : "\nAll protection checks passed");
process.exit(failures ? 1 : 0);
