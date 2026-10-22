/**
 * SMS two-factor against a mock Twilio Verify on port 3995. Start the service with
 * TWILIO_TEST_BASE_URL=http://localhost:3995 and test TWILIO_* values (see .github/workflows/ci.yml).
 */
import { createServer } from "node:http";
import { randomInt } from "node:crypto";
import { sql } from "drizzle-orm";
import { seedInstance } from "./seed";
import { db, closeDb } from "../src/lib/db";
import { closeCache } from "../src/lib/cache";
import { invalidateInstance } from "../src/lib/auth/instance";
import { totpAt, currentCounter } from "../src/lib/auth/totp";
import { listAudit } from "../src/lib/audit";

const AUTH = "http://localhost:3000";
let failures = 0;
const check = (name: string, ok: boolean, detail?: unknown) => {
  console.log(`${ok ? "✓" : "✗"} ${name}${ok ? "" : ` — ${JSON.stringify(detail)?.slice(0, 300)}`}`);
  if (!ok) failures++;
};

// ---------- Mock Twilio Verify ----------
const SID = process.env.TWILIO_ACCOUNT_SID ?? "", TOKEN = process.env.TWILIO_AUTH_TOKEN ?? "";
const pending = new Map<string, string>(); // phone → code
const sent: string[] = [];
let mode: "ok" | "refuse" = "ok";
const twilio = createServer(async (req, res) => {
  let raw = "";
  for await (const c of req) raw += c;
  const f = new URLSearchParams(raw);
  const send = (status: number, body: unknown) => res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(body));
  if (req.headers.authorization !== `Basic ${Buffer.from(`${SID}:${TOKEN}`).toString("base64")}`) return send(401, { code: 20003 });
  if (req.url?.endsWith("/Verifications")) {
    if (mode === "refuse") return send(400, { code: 60200, message: "Invalid parameter" });
    const code = String(randomInt(0, 1_000_000)).padStart(6, "0");
    pending.set(f.get("To")!, code);
    sent.push(f.get("To")!);
    return send(201, { status: "pending", to: f.get("To") });
  }
  if (req.url?.endsWith("/VerificationCheck")) {
    const want = pending.get(f.get("To")!);
    if (!want) return send(404, { code: 20404 });
    if (want !== f.get("Code")) return send(200, { status: "pending" });
    pending.delete(f.get("To")!); // single use, like Twilio
    return send(200, { status: "approved" });
  }
  send(404, {});
});
await new Promise<void>((r) => twilio.listen(3995, r));
const lastCode = (phone: string) => pending.get(phone) ?? "";

// ---------- Helpers ----------
const seed = await seedInstance("SMS E2E", []);
const pk = seed.publishableKey;
const setSms = async (on: boolean) => {
  await db().execute(sql`update instances set settings = settings || ${JSON.stringify({ smsSecondFactor: on })}::jsonb where id = ${seed.instanceId}`);
  await invalidateInstance(seed.instanceId);
};
class Browser {
  cookies = new Map<string, string>();
  async post(path: string, body?: unknown, method = "POST") {
    const r = await fetch(`${AUTH}/v1/client/${path}`, {
      method,
      headers: { "content-type": "application/json", "x-publishable-key": pk, origin: AUTH, "x-forwarded-for": `198.51.100.${randomInt(1, 250)}`, cookie: [...this.cookies].map(([k, v]) => `${k}=${v}`).join("; ") },
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
const pw = "a long enough password";
async function newUser(tag: string) {
  const b = new Browser();
  const email = `${tag}.${Date.now()}.${randomInt(1000)}@example.com`;
  const r = await b.post("sign_up", { email, password: pw });
  return { b, email, id: r.body.user.id as string };
}

// ---------- Off unless allowed ----------
const u1 = await newUser("ann");
check("off by default: environment says so", (await u1.b.post("environment", undefined, "GET")).body.smsSecondFactor === false);
check("off by default: adding a phone is refused", (await u1.b.post("mfa/sms", { phone: "+14155550100" })).body.error?.code === "sms_disabled");
await setSms(true);
check("turned on: environment says so", (await u1.b.post("environment", undefined, "GET")).body.smsSecondFactor === true);

// ---------- Enrolment ----------
check("a malformed number is refused", (await u1.b.post("mfa/sms", { phone: "555-0100" })).body.error?.code === "invalid_phone");
const PHONE = `+1415555${String(randomInt(1000, 9999))}`;
const st = await u1.b.post("mfa/sms", { phone: PHONE.replace(/^(\+1)(\d{3})(\d{3})/, "$1 ($2) $3-") });
check("add a phone: texts a code to the normalized number, shows it masked", st.status === 200 && sent.at(-1) === PHONE && st.body.phone.endsWith(PHONE.slice(-4)) && !st.body.phone.includes(PHONE.slice(2, 8)), st.body);
const stored = JSON.stringify(await db().execute(sql`select phone_enc, phone_index from mfa_sms where user_id = ${u1.id}`));
check("the number is encrypted at rest", stored.length > 20 && !stored.includes(PHONE) && !stored.includes(PHONE.slice(1)));
check("a wrong code doesn't confirm", (await u1.b.post("mfa/sms/verify", { code: "000000" })).body.error?.code === "invalid_code");
const conf = await u1.b.post("mfa/sms/verify", { code: lastCode(PHONE) });
check("the right code turns two-factor on and returns 10 backup codes", conf.status === 200 && conf.body.backupCodes.length === 10, conf.body);
const sec = await u1.b.post("me/security", undefined, "GET");
check("account shows SMS on, number masked", sec.body.twoFactorEnabled && sec.body.smsPhone?.endsWith(PHONE.slice(-4)) && !sec.body.totpEnabled && !JSON.stringify(sec.body).includes(PHONE), sec.body);
check("can't add a second phone", (await u1.b.post("mfa/sms", { phone: "+14155550199" })).body.error?.code === "already_enabled");

// ---------- Sign-in ----------
const s = new Browser();
const si = await s.post("sign_in", { email: u1.email, password: pw });
check("password sign-in now needs a second factor", si.body.status === "needs_second_factor" && !si.body.jwt);
const opts = await s.post("sign_in/second_factor/options");
check("options: SMS (masked), no authenticator app", opts.body.sms?.endsWith(PHONE.slice(-4)) && opts.body.totp === false && opts.body.backupCodes === true && !JSON.stringify(opts.body).includes(PHONE), opts.body);
check("options need the pending sign-in cookie", (await new Browser().post("sign_in/second_factor/options")).status === 401);
check("texting needs the pending sign-in cookie", (await new Browser().post("sign_in/second_factor/sms")).status === 401);
await s.post("sign_in/second_factor/sms");
const code1 = lastCode(PHONE);
check("a wrong texted code is refused", (await s.post("sign_in/second_factor", { code: "111111", method: "sms" })).body.error?.code === "invalid_code");
const fin = await s.post("sign_in/second_factor", { code: code1, method: "sms" });
check("the texted code completes sign-in", fin.status === 200 && fin.body.status === "complete" && !!fin.body.jwt, fin.body);
const s2 = new Browser();
await s2.post("sign_in", { email: u1.email, password: pw });
check("a used code can't be replayed", (await s2.post("sign_in/second_factor", { code: code1, method: "sms" })).body.error?.code === "invalid_code");
await s2.post("sign_in/second_factor/sms");
check("SMS-only account: a 6-digit code without `method` is checked as SMS", (await s2.post("sign_in/second_factor", { code: lastCode(PHONE) })).body.status === "complete");

// ---------- Adding the other factor needs a current code ----------
check("adding an authenticator app while SMS is on needs a code", (await u1.b.post("mfa/totp")).body.error?.code === "code_required");
await u1.b.post("mfa/sms/send");
const add = await u1.b.post("mfa/totp", { code: lastCode(PHONE) });
check("…and works with a texted code", add.status === 200 && /^[A-Z2-7]{32}$/.test(add.body.secret), add.body);
const tv = await u1.b.post("mfa/totp/verify", { code: totpAt(add.body.secret, currentCounter()) });
check("adding the second method keeps the existing backup codes", tv.status === 200 && tv.body.backupCodes.length === 0, tv.body);
const s3 = new Browser();
await s3.post("sign_in", { email: u1.email, password: pw });
await s3.post("sign_in/second_factor/sms");
check("with both methods, a texted code still works after 'Text me a code'", (await s3.post("sign_in/second_factor", { code: lastCode(PHONE) })).body.status === "complete");

const u2 = await newUser("ben");
const t2 = await u2.b.post("mfa/totp");
await u2.b.post("mfa/totp/verify", { code: totpAt(t2.body.secret, currentCounter()) });
check("adding a phone while an authenticator app is on needs a code (no silent takeover)", (await u2.b.post("mfa/sms", { phone: "+14155550123" })).body.error?.code === "code_required");
check("…and a wrong code is refused", (await u2.b.post("mfa/sms", { phone: "+14155550123", code: "123456" })).body.error?.code === "code_required");

// ---------- Removing ----------
check("removing the phone needs a code", (await u1.b.post("mfa/sms/remove", { code: "000000" })).body.error?.code === "invalid_code");
const rm = await u1.b.post("mfa/sms/remove", { code: totpAt(add.body.secret, currentCounter() + 1) });
check("…and works with an authenticator code", rm.status === 200);
const sec2 = await u1.b.post("me/security", undefined, "GET");
check("two-factor stays on through the authenticator app", sec2.body.twoFactorEnabled && sec2.body.smsPhone === null && sec2.body.totpEnabled, sec2.body);

// ---------- Limits and failures ----------
const u3 = await newUser("cal");
const P3 = `+4420${String(randomInt(10_000_000, 99_999_999))}`;
await u3.b.post("mfa/sms", { phone: P3 });
for (let i = 0; i < 4; i++) await u3.b.post("mfa/sms", { phone: P3 });
check("texts are rate limited per user and number", (await u3.b.post("mfa/sms", { phone: P3 })).status === 429);
const u4 = await newUser("dee");
mode = "refuse";
check("if Twilio refuses the number, a clear error", (await u4.b.post("mfa/sms", { phone: "+14155550177" })).body.error?.code === "sms_failed");
mode = "ok";

const u5 = await newUser("eve");
const P5 = `+1650555${String(randomInt(1000, 9999))}`;
await u5.b.post("mfa/sms", { phone: P5 });
await u5.b.post("mfa/sms/verify", { code: lastCode(P5) });
await u5.b.post("mfa/sms/send");
const off = await u5.b.post("mfa/totp/disable", { code: lastCode(P5) });
check("turning two-factor off with a texted code removes the phone too", off.status === 200 && (await u5.b.post("me/security", undefined, "GET")).body.smsPhone === null);

await setSms(false);
const sOff = new Browser();
check("if the app turns SMS off, nobody is locked out: sign-in still asks for 2FA", (await sOff.post("sign_in", { email: u2.email, password: pw })).body.status === "needs_second_factor");

await new Promise((r) => setTimeout(r, 400));
const audit = (await listAudit(seed.instanceId, { limit: 200 })).data;
check("audit log records SMS enable/disable", audit.some((e) => e.type === "user.two_factor_enabled" && e.data?.method === "sms") && audit.some((e) => e.type === "user.two_factor_disabled" && e.data?.method === "sms"));

twilio.close();
await closeDb();
await closeCache();
console.log(failures ? `\n${failures} check(s) failed` : "\nAll SMS two-factor checks passed");
process.exit(failures ? 1 : 0);
