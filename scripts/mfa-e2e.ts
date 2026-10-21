/** Two-factor (TOTP + backup codes) checks. Needs the service on :3000. */
import { sql } from "drizzle-orm";
import { seedInstance } from "./seed";
import { db, closeDb } from "../src/lib/db";
import { closeCache } from "../src/lib/cache";
import { totpAt, currentCounter } from "../src/lib/auth/totp";

const AUTH = "http://localhost:3000";
let failures = 0;
const check = (name: string, ok: boolean, detail?: unknown) => {
  console.log(`${ok ? "✓" : "✗"} ${name}${ok ? "" : ` — ${JSON.stringify(detail)}`}`);
  if (!ok) failures++;
};

const { publishableKey: pk, secretKey: sk } = await seedInstance("MFA E2E", []);

class Browser {
  cookies = new Map<string, string>();
  async post(path: string, body?: unknown) {
    const res = await fetch(`${AUTH}/v1/client/${path}`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-publishable-key": pk, origin: AUTH, cookie: [...this.cookies].map(([k, v]) => `${k}=${v}`).join("; ") },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    for (const c of res.headers.getSetCookie()) {
      const kv = c.split(";")[0];
      const k = kv.slice(0, kv.indexOf("=")), v = kv.slice(kv.indexOf("=") + 1);
      if (/max-age=0/i.test(c) || !v) this.cookies.delete(k);
      else this.cookies.set(k, v);
    }
    return { status: res.status, body: await res.json() };
  }
  has(prefix: string) {
    return [...this.cookies.keys()].some((k) => k.startsWith(prefix));
  }
}

const email = `tfa.${Date.now()}@example.com`;
const password = "a solid passphrase";
const me = new Browser();
await me.post("sign_up", { email, password });

// ---------- Enrollment ----------
const start = await me.post("mfa/totp");
const secret: string = start.body.secret;
check("enrollment returns secret + otpauth URI with issuer", /^[A-Z2-7]{32}$/.test(secret) && start.body.uri.startsWith("otpauth://totp/MFA%20E2E:") && start.body.uri.includes("issuer=MFA+E2E"), start.body);
check("enrollment requires a session", (await new Browser().post("mfa/totp")).status === 401);
const c0 = currentCounter();
check("confirm with wrong code → invalid_code", (await me.post("mfa/totp/verify", { code: totpAt(secret, c0 + 5) })).body.error?.code === "invalid_code");
const confirm = await me.post("mfa/totp/verify", { code: totpAt(secret, c0) });
const backup: string[] = confirm.body.backupCodes ?? [];
check("confirm returns 10 backup codes", confirm.status === 200 && backup.length === 10 && backup.every((c) => /^[a-z2-9]{5}-[a-z2-9]{5}$/.test(c)), confirm.body);
check("user shows twoFactorEnabled", (await (await fetch(`${AUTH}/v1/client/session?pk=${pk}`, { headers: { cookie: [...me.cookies].map(([k, v]) => `${k}=${v}`).join("; ") } })).json()).user.twoFactorEnabled === true);
check("can't start enrollment again while enabled", (await me.post("mfa/totp")).body.error?.code === "already_enabled");

const dbDump = JSON.stringify(await db().execute(sql`select t.secret_enc, b.code_hash from mfa_totp t join backup_codes b on b.user_id = t.user_id`));
check("TOTP secret encrypted at rest", !dbDump.includes(secret));
check("backup codes stored only as hashes", !backup.some((c) => dbDump.includes(c) || dbDump.includes(c.replace("-", ""))));

// ---------- Sign-in now needs a second factor ----------
const b1 = new Browser();
const s1 = await b1.post("sign_in", { email, password });
check("password alone → needs_second_factor, no session", s1.body.status === "needs_second_factor" && !s1.body.jwt && !b1.has("__dw_rt_"), s1.body);
check("pending cookie is set", b1.has("__dw_2fa_"));
check("no token can be minted before the second factor", (await b1.post("session/token")).status === 401);
check("replayed code (already used at setup) is rejected", (await b1.post("sign_in/second_factor", { code: totpAt(secret, c0) })).body.error?.code === "invalid_code");
const ok1 = await b1.post("sign_in/second_factor", { code: totpAt(secret, c0 + 1) });
check("valid authenticator code completes sign-in", ok1.status === 200 && ok1.body.status === "complete" && !!ok1.body.jwt && b1.has("__dw_rt_") && !b1.has("__dw_2fa_"), ok1.body);
check("same code can't be used twice", await (async () => {
  const b = new Browser();
  await b.post("sign_in", { email, password });
  return (await b.post("sign_in/second_factor", { code: totpAt(secret, c0 + 1) })).body.error?.code === "invalid_code";
})());

// Backup code path
const b2 = new Browser();
await b2.post("sign_in", { email, password });
check("backup code completes sign-in (case/dash-insensitive)", (await b2.post("sign_in/second_factor", { code: backup[0].toUpperCase().replace("-", "") })).status === 200);
const b3 = new Browser();
await b3.post("sign_in", { email, password });
check("backup code is single-use", (await b3.post("sign_in/second_factor", { code: backup[0] })).body.error?.code === "invalid_code");

// Brute force: 5 wrong codes voids the attempt
const b4 = new Browser();
await b4.post("sign_in", { email, password });
for (let i = 0; i < 5; i++) await b4.post("sign_in/second_factor", { code: "000000" });
check("attempt voided after 5 wrong codes (even a right code fails)", (await b4.post("sign_in/second_factor", { code: backup[1] })).status === 401);
check("second factor without the pending cookie → 401", (await new Browser().post("sign_in/second_factor", { code: backup[1] })).status === 401);

// ---------- Management ----------
check("regenerate requires a valid code", (await me.post("mfa/backup_codes", { code: "000000" })).body.error?.code === "invalid_code");
const rot = await me.post("mfa/backup_codes", { code: backup[2] });
check("regenerate returns 10 new codes", rot.body.backupCodes?.length === 10);
const b5 = new Browser();
await b5.post("sign_in", { email, password });
check("old backup codes stop working after regenerate", (await b5.post("sign_in/second_factor", { code: backup[3] })).body.error?.code === "invalid_code");
check("disable requires a valid code", (await me.post("mfa/totp/disable", { code: "123456" })).body.error?.code === "invalid_code");
check("disable with a valid code", (await me.post("mfa/totp/disable", { code: totpAt(secret, c0 - 1) })).body.enabled === false);
check("sign-in no longer asks for a second factor", (await new Browser().post("sign_in", { email, password })).body.status === "complete");

// ---------- Admin reset ----------
const me2 = new Browser();
await me2.post("sign_up", { email: `adm.${email}`, password });
const st = await me2.post("mfa/totp");
await me2.post("mfa/totp/verify", { code: totpAt(st.body.secret, currentCounter()) });
const userId = (await me2.post("session/token")).body.userId;
const reset = await fetch(`${AUTH}/v1/users/${userId}/mfa`, { method: "DELETE", headers: { authorization: `Bearer ${sk}` } });
check("backend API can reset a user's 2FA", reset.status === 200 && (await new Browser().post("sign_in", { email: `adm.${email}`, password })).body.status === "complete");

await closeDb();
await closeCache();
console.log(failures ? `\n${failures} check(s) failed` : "\nAll 2FA checks passed");
process.exit(failures ? 1 : 0);
