/**
 * Test mode: fixed code 424242 for +daywalker_test emails and reserved test phone numbers on a development
 * instance, nothing sent, and a clear refusal everywhere else (production, platform, cloning, domain trust).
 * Starts a mock Twilio on 3995 to prove no text goes out for test numbers.
 */
import { createServer } from "node:http";
import { randomInt } from "node:crypto";
import { eq, sql } from "drizzle-orm";
import { seedInstance } from "./seed";
import { db, schema, closeDb } from "../src/lib/db";
import { cache, closeCache } from "../src/lib/cache";
import { blindIndex } from "../src/lib/crypto";
import { invalidateInstance } from "../src/lib/auth/instance";
import { createEnvironmentInstance } from "../src/lib/auth/application";
import { createBackendClient, testEmail, testPhone, isTestEmail, isTestPhone, TEST_CODE } from "../packages/sdk/src/server";

const AUTH = "http://localhost:3000";
let failures = 0;
const check = (name: string, ok: boolean, detail?: unknown) => {
  console.log(`${ok ? "✓" : "✗"} ${name}${ok ? "" : ` — ${JSON.stringify(detail)?.slice(0, 400)}`}`);
  if (!ok) failures++;
};

// Mock Twilio: records every text it is asked to send.
const SID = process.env.TWILIO_ACCOUNT_SID ?? "", TOKEN = process.env.TWILIO_AUTH_TOKEN ?? "";
const texted: string[] = [];
const pending = new Map<string, string>();
const twilio = createServer(async (req, res) => {
  let raw = "";
  for await (const c of req) raw += c;
  const f = new URLSearchParams(raw);
  const send = (status: number, body: unknown) => res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(body));
  if (req.headers.authorization !== `Basic ${Buffer.from(`${SID}:${TOKEN}`).toString("base64")}`) return send(401, {});
  if (req.url?.endsWith("/Verifications")) {
    const code = String(randomInt(100000, 999999));
    pending.set(f.get("To")!, code);
    texted.push(f.get("To")!);
    return send(201, { status: "pending" });
  }
  if (req.url?.endsWith("/VerificationCheck")) {
    const ok = pending.get(f.get("To")!) === f.get("Code");
    if (ok) pending.delete(f.get("To")!);
    return send(200, { status: ok ? "approved" : "pending" });
  }
  send(404, {});
});
await new Promise<void>((r) => twilio.listen(3995, r));

class Browser {
  cookies = new Map<string, string>();
  constructor(public pk: string) {}
  async post(path: string, body?: unknown, method = "POST") {
    const r = await fetch(`${AUTH}/v1/client/${path}`, {
      method,
      headers: { "content-type": "application/json", "x-publishable-key": this.pk, origin: AUTH, "x-forwarded-for": `198.51.100.${randomInt(1, 250)}`, cookie: [...this.cookies].map(([k, v]) => `${k}=${v}`).join("; ") },
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
}
const mail = async (to: string) => (await cache().get(`devmail:${blindIndex(to, "devmail")}`)) ?? null;
const code = (r: { body: { error?: { code?: string } } | null }) => r.body?.error?.code;
const pw = "a long enough password";
const setSettings = async (instanceId: string, patch: Record<string, unknown>) => {
  const [i] = await db().select().from(schema.instances).where(eq(schema.instances.id, instanceId));
  await db().update(schema.instances).set({ settings: { ...i.settings, ...patch } }).where(eq(schema.instances.id, instanceId));
  await invalidateInstance(instanceId);
};

const inst = await seedInstance("Test mode E2E");
const be = createBackendClient({ secretKey: inst.secretKey, apiUrl: AUTH });
const prod = await createEnvironmentInstance(inst.accountId, { name: "Test mode E2E", environment: "production", applicationId: inst.applicationId });
const beProd = createBackendClient({ secretKey: prod.secretKey, apiUrl: AUTH });
await setSettings(inst.instanceId, { emailCodeSignIn: true, smsSecondFactor: true });
await setSettings(prod.instance.id, { emailCodeSignIn: true, smsSecondFactor: true });

// ---------- SDK helpers ----------
check("helpers build and recognise test values", isTestEmail(testEmail("ann")) && testEmail("ann") === "ann+daywalker_test@example.com" && isTestPhone(testPhone(7)) && testPhone(7) === "+15555550107" && TEST_CODE === "424242");
check("lookalikes aren't test values", !isTestEmail("ann+daywalker_testing@example.com") && !isTestEmail("daywalker_test@example.com") && !isTestPhone("+15555550200") && !isTestPhone("+14155550100") && isTestEmail("ann+daywalker_test+2@example.com"));

// ---------- The switch ----------
const tm0 = await be.testMode.get();
check("development: available, off by default", tm0.available && !tm0.enabled && tm0.code === "424242", tm0);
check("environment reports test mode off", (await new Browser(inst.publishableKey).post("environment", undefined, "GET")).body.testMode === false);
check("unauthenticated change refused", (await fetch(`${AUTH}/v1/instance/test_mode`, { method: "PATCH", body: "{}" })).status === 401);
check("invalid body rejected (422)", (await fetch(`${AUTH}/v1/instance/test_mode`, { method: "PATCH", headers: { authorization: `Bearer ${inst.secretKey}`, "content-type": "application/json" }, body: JSON.stringify({ enabled: "yes" }) })).status === 422);

// ---------- Off: test addresses are ordinary addresses ----------
const off = new Browser(inst.publishableKey);
const offEmail = testEmail("off", { unique: true });
await off.post("sign_up", { email: offEmail, password: pw });
await off.post("email/send_code");
const offMail = await mail(offEmail);
check("test mode off: a real code is emailed", !!offMail && /\b\d{6}\b/.test(offMail) && !offMail.includes("424242"), offMail);
check("test mode off: 424242 does not verify", code(await off.post("email/verify", { code: "424242" })) === "invalid_code");
check("test mode off: a reserved phone number is refused with a clear error", code(await off.post("mfa/sms", { phone: testPhone(1) })) === "test_phone_unavailable");

// ---------- On ----------
const on = await be.testMode.set(true);
check("turned on", on.enabled && on.available);
check("environment reports test mode on", (await new Browser(inst.publishableKey).post("environment", undefined, "GET")).body.testMode === true);

// Verification
const a = new Browser(inst.publishableKey);
const aEmail = testEmail("alice", { unique: true });
const su = await a.post("sign_up", { email: aEmail, password: pw });
check("sign-up with a test address works", su.status === 200 || su.status === 201, su);
check("send verification code", (await a.post("email/send_code")).status === 200);
check("…and no email was sent", (await mail(aEmail)) === null);
check("a wrong code still fails", code(await a.post("email/verify", { code: "123456" })) === "invalid_code");
check("424242 verifies the address", (await a.post("email/verify", { code: "424242" })).status === 200);
const realEmail = `real.${Date.now()}@example.com`;
const real = new Browser(inst.publishableKey);
await real.post("sign_up", { email: realEmail, password: pw });
await real.post("email/send_code");
const realMail = await mail(realEmail);
check("real addresses still get a real random code by email", !!realMail && /\b\d{6}\b/.test(realMail) && !realMail.includes("424242"));
check("…and 424242 doesn't work for them", code(await real.post("email/verify", { code: "424242" })) === "invalid_code");

// Email code sign-in
const out = new Browser(inst.publishableKey);
check("email sign-in code: sent without mail", (await out.post("sign_in/email_code", { email: aEmail })).status === 200 && (await mail(aEmail)) === null);
const signedIn = await out.post("sign_in/email_code/verify", { email: aEmail, code: "424242" });
check("424242 signs in", signedIn.status === 200 && signedIn.body.status === "complete" && !!signedIn.body.jwt, signedIn.body);
check("wrong code is refused and counted (5 tries then burned)", await (async () => {
  const b = new Browser(inst.publishableKey);
  await b.post("sign_in/email_code", { email: aEmail });
  let last;
  for (let i = 0; i < 6; i++) last = await b.post("sign_in/email_code/verify", { email: aEmail, code: String(100000 + i) });
  return code(last!) === "invalid_code" && code(await b.post("sign_in/email_code/verify", { email: aEmail, code: "424242" })) === "invalid_code";
})());
check("424242 doesn't sign in a real address", await (async () => {
  const b = new Browser(inst.publishableKey);
  await b.post("sign_in/email_code", { email: realEmail });
  return code(await b.post("sign_in/email_code/verify", { email: realEmail, code: "424242" })) === "invalid_code";
})());

// Password reset
const rs = new Browser(inst.publishableKey);
check("password reset: accepted, no mail", (await rs.post("password/forgot", { email: aEmail })).status === 200 && (await mail(aEmail)) === null);
const reset = await rs.post("password/reset", { email: aEmail, code: "424242", password: "another long password" });
check("password reset with 424242 works", reset.status === 200, reset.body);
check("the new password signs in", (await new Browser(inst.publishableKey).post("sign_in", { email: aEmail, password: "another long password" })).status === 200);

// SMS
const p = new Browser(inst.publishableKey);
const pEmail = `phone.${Date.now()}@example.com`;
await p.post("sign_up", { email: pEmail, password: pw });
const before = texted.length;
const phone = testPhone(randomInt(0, 100));
const st = await p.post("mfa/sms", { phone });
check("test phone number: enrolment starts without texting", st.status === 200 && texted.length === before, st);
check("a wrong code fails", code(await p.post("mfa/sms/verify", { code: "000000" })) === "invalid_code");
const conf = await p.post("mfa/sms/verify", { code: "424242" });
check("424242 confirms the number and turns on two-factor", conf.status === 200 && conf.body.backupCodes?.length === 10, conf);
check("the number is stored encrypted", !JSON.stringify((await db().execute(sql`select phone_enc from mfa_sms`)).slice(0, 1000)).includes(phone.slice(1)));
const sf = new Browser(inst.publishableKey);
const si = await sf.post("sign_in", { email: pEmail, password: pw });
check("sign-in needs a second factor", si.body.status === "needs_second_factor");
check("texting the test number sends nothing", (await sf.post("sign_in/second_factor/sms")).status === 200 && texted.length === before);
const fin = await sf.post("sign_in/second_factor", { code: "424242", method: "sms" });
check("424242 completes the SMS second factor", fin.status === 200 && fin.body.status === "complete", fin.body);
// a real number still goes through Twilio
const q = new Browser(inst.publishableKey);
await q.post("sign_up", { email: `phone2.${Date.now()}@example.com`, password: pw });
await q.post("mfa/sms", { phone: `+1415555${randomInt(1000, 9999)}` });
check("a real number still goes through the SMS provider", texted.length === before + 1);
check("424242 doesn't confirm a real number", code(await q.post("mfa/sms/verify", { code: "424242" })) === "invalid_code");

// ---------- Not for domain trust ----------
const [{ n }] = (await db().execute(sql`select count(*)::int n from email_addresses where instance_id = ${inst.instanceId} and verified_at is not null`)) as unknown as { n: number }[];
check("test addresses can be verified", n >= 1);
const orgOwner = new Browser(inst.publishableKey);
await orgOwner.post("sign_up", { email: `owner.${Date.now()}@acme.example`, password: pw });
const org = await orgOwner.post("organizations", { name: "Acme" });
const orgId = org.body.organization?.id as string;
const dom = await be.organizationDomains.add(orgId, "acme-test.example");
await db().update(schema.orgDomains).set({ verifiedAt: new Date(), verifiedVia: "dns", enrollment: "auto_join" }).where(eq(schema.orgDomains.id, dom.id));
await cache().del(`orgdom:${inst.instanceId}`);
const tu = new Browser(inst.publishableKey);
const tEmail = testEmail("joiner", { domain: "acme-test.example", unique: true });
await tu.post("sign_up", { email: tEmail, password: pw });
await tu.post("email/send_code");
await tu.post("email/verify", { code: "424242" });
await new Promise((r) => setTimeout(r, 400));
const orgs = await tu.post("organizations", undefined, "GET");
check("a test address doesn't auto-join an organization by domain", (orgs.body.organizations ?? []).length === 0, orgs.body);
const ru = new Browser(inst.publishableKey);
const rEmail = `real.join.${Date.now()}@acme-test.example`;
await ru.post("sign_up", { email: rEmail, password: pw });
await ru.post("email/send_code");
const rCode = (await mail(rEmail))?.match(/\b(\d{6})\b/)?.[1];
await ru.post("email/verify", { code: rCode ?? "000000" });
await new Promise((r) => setTimeout(r, 400));
check("(control) a real verified address at the same domain does auto-join", ((await ru.post("organizations", undefined, "GET")).body.organizations ?? []).length === 1);

// ---------- Production refuses ----------
check("production: cannot be turned on (403)", await (async () => { try { await beProd.testMode.set(true); return false; } catch (e) { return (e as { status: number; code: string }).status === 403 && (e as { code: string }).code === "test_mode_unavailable"; } })());
check("production: reports unavailable and off", await (async () => { const t = await beProd.testMode.get(); return !t.available && !t.enabled; })());
check("production: turning it off is allowed", (await beProd.testMode.set(false)).enabled === false);
// Even if the flag were stored on a production instance, it is ignored
await setSettings(prod.instance.id, { testMode: { enabled: true } });
check("a stored flag on production is ignored", !(await beProd.testMode.get()).enabled && (await new Browser(prod.publishableKey).post("environment", undefined, "GET")).body.testMode === false);
const pb = new Browser(prod.publishableKey);
const prodTest = await pb.post("sign_up", { email: testEmail("prod", { unique: true }), password: pw });
check("production: sign-up with a test address is refused with a clear error", prodTest.status === 400 && code(prodTest) === "test_mode_unavailable" && /development/.test(prodTest.body.error.message), prodTest.body);
check("production: sign-in code to a test address is refused", code(await pb.post("sign_in/email_code", { email: testEmail("prod2") })) === "test_mode_unavailable");
check("production: password reset for a test address is refused", code(await pb.post("password/forgot", { email: testEmail("prod3") })) === "test_mode_unavailable");
const pr = new Browser(prod.publishableKey);
await pr.post("sign_up", { email: `prodreal.${Date.now()}@example.com`, password: pw });
check("production: a test phone number is refused", code(await pr.post("mfa/sms", { phone: testPhone(5) })) === "test_phone_unavailable");
check("production: 424242 verifies nothing", await (async () => { await pr.post("email/send_code"); return code(await pr.post("email/verify", { code: "424242" })) === "invalid_code"; })());
check("production: ordinary addresses are unaffected", (await pr.post("environment", undefined, "GET")).status === 200);

// ---------- Cloning never carries it ----------
const cloneRes = await fetch(`${AUTH}/v1/instance/clone`, { method: "POST", headers: { authorization: `Bearer ${prod.secretKey}`, "content-type": "application/json" }, body: JSON.stringify({}) });
const cl = await cloneRes.json();
const [pi] = await db().select().from(schema.instances).where(eq(schema.instances.id, prod.instance.id));
check("cloning dev -> prod skips test mode and reports it", cloneRes.status === 200 && cl.skipped.some((s: { what: string }) => s.what === "settings.testMode"), cl.skipped);
check("…and production still reports test mode off", !(await beProd.testMode.get()).enabled);
void pi;

// ---------- Platform instance never honors it ----------
const platform = await seedInstance("Fake platform");
process.env.PLATFORM_PUBLISHABLE_KEY = platform.publishableKey;
const { testModeActive, testModeAvailable } = await import("../src/lib/auth/test-mode");
const [pf] = await db().select().from(schema.instances).where(eq(schema.instances.id, platform.instanceId));
check("the platform's own instance can't use test mode", !testModeAvailable(pf) && !testModeActive({ ...pf, settings: { ...pf.settings, testMode: { enabled: true } } }));
delete process.env.PLATFORM_PUBLISHABLE_KEY;

// ---------- Audit ----------
const audit = await fetch(`${AUTH}/v1/audit_events?type=instance.test_mode_updated`, { headers: { authorization: `Bearer ${inst.secretKey}` } });
check("audit records the toggle", (await audit.json()).data.length >= 1);

twilio.close();
console.log(failures ? `\n${failures} check(s) failed` : "\nAll test mode checks passed");
await closeDb();
await closeCache();
process.exit(failures ? 1 : 0);
