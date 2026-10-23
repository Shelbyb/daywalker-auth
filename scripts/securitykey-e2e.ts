/**
 * Security keys as a second factor, with a software authenticator that makes real WebAuthn
 * messages (see soft-authenticator.ts). Needs the service on :3000 (RP ID "localhost").
 */
import { randomInt } from "node:crypto";
import { sql } from "drizzle-orm";
import { seedInstance } from "./seed";
import { db, closeDb } from "../src/lib/db";
import { closeCache } from "../src/lib/cache";
import { listAudit } from "../src/lib/audit";
import { totpAt, currentCounter } from "../src/lib/auth/totp";
import { SoftAuthenticator, b64u, AUTH } from "./soft-authenticator";

let failures = 0;
const check = (name: string, ok: boolean, detail?: unknown) => {
  console.log(`${ok ? "✓" : "✗"} ${name}${ok ? "" : ` — ${JSON.stringify(detail)?.slice(0, 400)}`}`);
  if (!ok) failures++;
};

const seed = await seedInstance("Security Key E2E", []);
const pk = seed.publishableKey;

class Browser {
  cookies = new Map<string, string>();
  async call(method: string, path: string, body?: unknown) {
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
  post = (path: string, body?: unknown) => this.call("POST", path, body);
  get = (path: string) => this.call("GET", path);
}
const pw = "a long enough password";
async function newUser(tag: string) {
  const b = new Browser();
  const email = `${tag}.${Date.now()}.${randomInt(1000)}@example.com`;
  const r = await b.post("sign_up", { email, password: pw });
  return { b, email, id: r.body.user.id as string };
}
const code = (r: { body: { error?: { code?: string } } | null }) => r.body?.error?.code;

/** Register `key` for the user. `currentCode` is needed when two-factor is already on. */
async function register(u: Awaited<ReturnType<typeof newUser>>, key: SoftAuthenticator, name?: string, currentCode?: string) {
  const o = await u.b.post("mfa/security_keys/register/options", currentCode ? { code: currentCode } : {});
  if (o.status !== 200) return { options: o, verify: null };
  const verify = await u.b.post("mfa/security_keys/register/verify", { response: key.register(o.body, { uv: false }), name });
  return { options: o, verify };
}

// ---------- Registration ----------
const ann = await newUser("ann");
const keyA = new SoftAuthenticator();
const o1 = await ann.b.post("mfa/security_keys/register/options", {});
check("registration options: not a resident key, and a user handle that can't clash with a passkey", o1.status === 200 && o1.body.authenticatorSelection?.residentKey === "discouraged" && Buffer.from(o1.body.user.id, "base64url").toString() === `sk:${ann.id}`, o1.body);
check("registration needs a signed-in session", (await new Browser().post("mfa/security_keys/register/options", {})).status === 401);
const bad = await ann.b.post("mfa/security_keys/register/verify", { response: keyA.register(o1.body, { challenge: b64u(Buffer.from("not the challenge")) }), name: "x" });
check("an answer to a different challenge is refused", bad.status === 400 && code(bad) === "security_key_invalid", bad.body);
const lost = await ann.b.post("mfa/security_keys/register/verify", { response: keyA.register(o1.body), name: "x" });
check("…and the challenge was used up by that attempt", lost.status === 400 && code(lost) === "challenge_expired", lost.body);
const reg = await register(ann, keyA, "YubiKey 5");
check("a valid key registers, turns two-factor on and returns 10 backup codes", reg.verify?.status === 201 && reg.verify.body.backupCodes.length === 10, reg.verify?.body);
const backups: string[] = reg.verify?.body.backupCodes ?? [];
const sec = await ann.b.get("me/security");
check("account shows the key, two-factor on, no authenticator app or phone", sec.body.twoFactorEnabled === true && sec.body.totpEnabled === false && sec.body.smsPhone === null && sec.body.securityKeys.length === 1 && sec.body.securityKeys[0].name === "YubiKey 5", sec.body);
check("the public key isn't exposed", !JSON.stringify(sec.body).includes("publicKey") && !JSON.stringify(sec.body).includes(b64u(keyA.credId)));
const dup = await register(ann, keyA, "again", backups[0]);
check("the same key can't be registered twice", dup.verify?.status === 409 || code(dup.verify!) === "security_key_exists", dup.verify?.body);
backups.shift(); // that code was spent by the attempt above

// ---------- Signing in ----------
const s1 = new Browser();
const si = await s1.post("sign_in", { email: ann.email, password: pw });
check("password sign-in now needs a second factor", si.body.status === "needs_second_factor" && !si.body.jwt, si.body);
const opts = await s1.post("sign_in/second_factor/options");
check("options: security key offered, nothing else but backup codes", opts.body.securityKey === true && opts.body.totp === false && opts.body.sms === null && opts.body.backupCodes === true, opts.body);
check("the challenge needs the pending sign-in cookie", (await new Browser().post("sign_in/second_factor/security_key")).status === 401);
const ch1 = await s1.post("sign_in/second_factor/security_key");
check("the challenge only allows this person's keys", ch1.status === 200 && ch1.body.allowCredentials?.length === 1 && ch1.body.allowCredentials[0].id === b64u(keyA.credId), ch1.body);

const forgery = new SoftAuthenticator();
forgery.credId = keyA.credId; // same credential ID, different private key
const f = await s1.post("sign_in/second_factor", { response: forgery.assert(ch1.body.challenge, { uv: false }) });
check("a forged signature is refused", f.status === 400 && code(f) === "security_key_invalid", f.body);
const again = await s1.post("sign_in/second_factor", { response: keyA.assert(ch1.body.challenge, { uv: false }) });
check("…and the challenge can't be retried after a failed answer", again.status === 400, again.body);

const ch2 = await s1.post("sign_in/second_factor/security_key");
const goodAssert = keyA.assert(ch2.body.challenge, { uv: false });
const ok = await s1.post("sign_in/second_factor", { response: goodAssert });
check("the right key completes sign-in", ok.status === 200 && ok.body.status === "complete" && !!ok.body.jwt, ok.body);
check("…and the pending sign-in is gone", (await s1.post("sign_in/second_factor/options")).status === 401);

const s2 = new Browser();
await s2.post("sign_in", { email: ann.email, password: pw });
await s2.post("sign_in/second_factor/security_key");
const replay = await s2.post("sign_in/second_factor", { response: goodAssert });
check("an old answer can't be replayed at a new sign-in", replay.status === 400, replay.body);

const s3 = new Browser();
await s3.post("sign_in", { email: ann.email, password: pw });
const noChallenge = await s3.post("sign_in/second_factor", { response: keyA.assert(b64u(Buffer.from("made up")), { uv: false }) });
check("an answer without asking for a challenge first is refused", noChallenge.status === 400, noChallenge.body);

const s4 = new Browser();
await s4.post("sign_in", { email: ann.email, password: pw });
const ch4 = await s4.post("sign_in/second_factor/security_key");
const cloned = keyA.assert(ch4.body.challenge, { uv: false, counter: 1 }); // counter went backwards: a cloned key
check("a key whose counter went backwards is refused", (await s4.post("sign_in/second_factor", { response: cloned })).status === 400);

// ---------- Another person's key ----------
const ben = await newUser("ben");
const keyB = new SoftAuthenticator();
await register(ben, keyB, "Ben's key");
const s5 = new Browser();
await s5.post("sign_in", { email: ann.email, password: pw });
const ch5 = await s5.post("sign_in/second_factor/security_key");
const wrongUser = await s5.post("sign_in/second_factor", { response: keyB.assert(ch5.body.challenge, { uv: false }) });
check("someone else's key can't answer for this account", wrongUser.status === 400, wrongUser.body);

// ---------- Not a sign-in on its own ----------
const po = await new Browser().post("passkeys/authenticate/options");
const alone = await new Browser().post("passkeys/authenticate/verify", { response: keyA.assert(po.body.challenge, { uv: true }) });
check("a security key can't sign in by itself (it isn't a passkey)", alone.status === 400 && !alone.body?.jwt, alone.body);

// ---------- Attempt limit ----------
const s6 = new Browser();
await s6.post("sign_in", { email: ann.email, password: pw });
let last = 0;
for (let i = 0; i < 6; i++) {
  await s6.post("sign_in/second_factor/security_key");
  last = (await s6.post("sign_in/second_factor", { response: forgery.assert(b64u(Buffer.from("x")), { uv: false }) })).status;
}
check("after 5 failures the sign-in attempt is void", last === 401);

// ---------- Adding and removing need a current code ----------
const noCode = await ann.b.post("mfa/security_keys/register/options", {});
check("adding a second key needs a current code", noCode.status === 400 && code(noCode) === "code_required", noCode.body);
check("a wrong code doesn't help", code(await ann.b.post("mfa/security_keys/register/options", { code: "000000" })) === "code_required");
const keyA2 = new SoftAuthenticator();
const second = await register(ann, keyA2, "Backup key", backups[0]);
backups.shift();
check("with a backup code, a second key is added and the existing backup codes are kept", second.verify?.status === 201 && second.verify.body.backupCodes.length === 0, second.verify?.body);
check("a TOTP app can't be added silently either", code(await ann.b.post("mfa/totp")) === "code_required");

const keys = (await ann.b.get("me/security")).body.securityKeys as { id: string; name: string }[];
check("both keys are listed", keys.length === 2, keys);
const rn = await ann.b.call("PATCH", `mfa/security_keys/${keys[1].id}`, { name: "Spare" });
check("a key can be renamed", rn.status === 200 && (await ann.b.get("me/security")).body.securityKeys.some((k: { name: string }) => k.name === "Spare"));
check("renaming someone else's key is a 404", (await ben.b.call("PATCH", `mfa/security_keys/${keys[0].id}`, { name: "mine now" })).status === 404);
check("removing needs a code", code(await ann.b.post(`mfa/security_keys/${keys[1].id}/remove`, { code: "000000" })) === "invalid_code");
check("someone else can't remove it", (await ben.b.post(`mfa/security_keys/${keys[0].id}/remove`, { code: "000000" })).status !== 200);
const rm = await ann.b.post(`mfa/security_keys/${keys[1].id}/remove`, { code: backups[0] });
backups.shift();
check("with a backup code, a key is removed", rm.status === 200 && (await ann.b.get("me/security")).body.securityKeys.length === 1, rm.body);
const s7 = new Browser();
await s7.post("sign_in", { email: ann.email, password: pw });
const ch7 = await s7.post("sign_in/second_factor/security_key");
check("the removed key no longer works", (await s7.post("sign_in/second_factor", { response: keyA2.assert(ch7.body.challenge, { uv: false }) })).status === 400);

const last1 = await ann.b.post(`mfa/security_keys/${keys[0].id}/remove`, { code: backups[0] });
backups.shift();
check("removing the last factor turns two-factor off", last1.status === 200 && (await ann.b.get("me/security")).body.twoFactorEnabled === false);
const left = (await db().execute(sql`select count(*)::int as n from backup_codes where user_id = ${ann.id}`)) as unknown as { n: number }[];
check("…and clears the backup codes", left[0].n === 0);
check("…so password sign-in completes again", (await new Browser().post("sign_in", { email: ann.email, password: pw })).body.status === "complete");

// ---------- Mixed with other factors, and admin reset ----------
const cy = await newUser("cy");
const t = await cy.b.post("mfa/totp");
await cy.b.post("mfa/totp/verify", { code: totpAt(t.body.secret, currentCounter()) });
const noC = await cy.b.post("mfa/security_keys/register/options", {});
check("with an authenticator app on, adding a key needs a code", code(noC) === "code_required");
const keyC = new SoftAuthenticator();
const addC = await register(cy, keyC, "Cy's key", totpAt(t.body.secret, currentCounter() + 1));
check("an authenticator code unlocks adding a key (no new backup codes)", addC.verify?.status === 201 && addC.verify.body.backupCodes.length === 0, addC.verify?.body);
const s8 = new Browser();
await s8.post("sign_in", { email: cy.email, password: pw });
const o8 = await s8.post("sign_in/second_factor/options");
check("both methods are offered", o8.body.totp === true && o8.body.securityKey === true, o8.body);
const ch8 = await s8.post("sign_in/second_factor/security_key");
check("either one signs in (the key here)", (await s8.post("sign_in/second_factor", { response: keyC.assert(ch8.body.challenge, { uv: false }) })).body.status === "complete");
const reset = await fetch(`${AUTH}/v1/users/${cy.id}/mfa`, { method: "DELETE", headers: { authorization: `Bearer ${seed.secretKey}` } });
const afterReset = (await db().execute(sql`select count(*)::int as n from mfa_security_keys where user_id = ${cy.id}`)) as unknown as { n: number }[];
check("the admin reset removes security keys too", reset.status === 200 && afterReset[0].n === 0);

// ---------- Limits and audit ----------
const dee = await newUser("dee");
const first = await register(dee, new SoftAuthenticator(), "k1");
const deeCodes: string[] = first.verify?.body.backupCodes ?? [];
for (let i = 2; i <= 5; i++) await register(dee, new SoftAuthenticator(), `k${i}`, deeCodes.shift());
check("an account can hold 5 keys", (await dee.b.get("me/security")).body.securityKeys.length === 5);
const sixth = await dee.b.post("mfa/security_keys/register/options", { code: deeCodes.shift() });
check("a 6th key is refused", sixth.status === 400 && code(sixth) === "too_many_keys", sixth.body);

// ---------- A key can confirm account changes (no code needed) ----------
const kay = await newUser("kay");
const keyK = new SoftAuthenticator();
const kayReg = await register(kay, keyK, "Kay's key");
const confirmKey = async (u: typeof kay, key: SoftAuthenticator) => {
  const o = await u.b.post("mfa/security_keys/confirm/options");
  if (o.status !== 200) return { options: o, confirm: null };
  return { options: o, confirm: await u.b.post("mfa/security_keys/confirm", { response: key.assert(o.body.challenge, { uv: false }) }) };
};
check("setup: key registered", kayReg.verify?.status === 201);
check("confirming needs a signed-in session", (await new Browser().post("mfa/security_keys/confirm/options")).status === 401);
check("a user with no keys can't ask for a key confirmation", code(await (await newUser("lee")).b.post("mfa/security_keys/confirm/options")) === "no_security_key");
check("without a confirmation, adding a key still needs a code", code(await kay.b.post("mfa/security_keys/register/options", {})) === "code_required");

const forged = await kay.b.post("mfa/security_keys/confirm/options");
const stranger = new SoftAuthenticator();
check("an answer from some other key is refused", (await kay.b.post("mfa/security_keys/confirm", { response: stranger.assert(forged.body.challenge, { uv: false }) })).status === 400);
check("…and opens nothing", code(await kay.b.post("mfa/security_keys/register/options", {})) === "code_required");

const c1 = await confirmKey(kay, keyK);
check("a touch of the key confirms", c1.confirm?.status === 200 && c1.confirm.body.confirmed === true, c1.confirm?.body);
const keyK2 = new SoftAuthenticator();
const addK2 = await register(kay, keyK2, "Second");
check("…so a second key can be added with no code", addK2.verify?.status === 201, addK2.verify?.body ?? addK2.options.body);
check("the confirmation is single use", code(await kay.b.post("mfa/security_keys/register/options", {})) === "code_required");

// Tied to the session that made it.
const kayOther = new Browser();
const sk = await kayOther.post("sign_in", { email: kay.email, password: pw });
const skCh = await kayOther.post("sign_in/second_factor/security_key");
await kayOther.post("sign_in/second_factor", { response: keyK.assert(skCh.body.challenge, { uv: false }) });
void sk;
await confirmKey(kay, keyK);
const kayKeys = (await kay.b.get("me/security")).body.securityKeys as { id: string }[];
check("another session can't use it", (await kayOther.post(`mfa/security_keys/${kayKeys[1].id}/remove`, {})).status === 400);
check("a missing code with no confirmation is refused", code(await kayOther.post("mfa/backup_codes", {})) === "invalid_code");
const fresh = await kay.b.post("mfa/backup_codes", {});
check("the confirming session can make new backup codes", fresh.status === 200 && fresh.body.backupCodes.length === 10, fresh.body);
await confirmKey(kay, keyK);
const rmK = await kay.b.post(`mfa/security_keys/${kayKeys[1].id}/remove`, {});
check("…or remove a key", rmK.status === 200 && (await kay.b.get("me/security")).body.securityKeys.length === 1, rmK.body);
await confirmKey(kay, keyK);
const offK = await kay.b.post("mfa/totp/disable", {});
check("…or turn two-factor off", offK.status === 200 && (await kay.b.get("me/security")).body.twoFactorEnabled === false, offK.body);
check("a wrong typed code still fails when no confirmation exists", code(await kay.b.post("mfa/totp/disable", { code: "000000" })) !== undefined);

await new Promise((r) => setTimeout(r, 400));
const audit = (await listAudit(seed.instanceId, { limit: 200 })).data;
check("audit log: keys added and removed", audit.some((e) => e.type === "user.two_factor_enabled" && e.data?.method === "security_key") && audit.some((e) => e.type === "user.two_factor_disabled" && e.data?.method === "security_key"));
check("audit log: failed key answers", audit.some((e) => e.type === "user.two_factor_failed" && e.data?.method === "security_key"));

await closeDb();
await closeCache();
console.log(failures ? `\n${failures} check(s) failed` : "\nAll security key checks passed");
process.exit(failures ? 1 : 0);
