/** Account lockout: progressive, identical for unknown accounts, 2FA counted, email unlock, admin unlock, events. */
import { sql } from "drizzle-orm";
import { seedInstance } from "./seed";
import { db, closeDb } from "../src/lib/db";
import { cache, closeCache } from "../src/lib/cache";
import { blindIndex } from "../src/lib/crypto";
import { totpAt, currentCounter } from "../src/lib/auth/totp";
import { createBackendClient } from "../packages/sdk/src/server";

const AUTH = "http://localhost:3000";
let failures = 0;
const check = (name: string, ok: boolean, detail?: unknown) => {
  console.log(`${ok ? "✓" : "✗"} ${name}${ok ? "" : ` — ${JSON.stringify(detail)?.slice(0, 400)}`}`);
  if (!ok) failures++;
};
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const rows = async (q: ReturnType<typeof sql>) => (await db().execute(q)) as unknown as Record<string, any>[];
const settle = () => new Promise((r) => setTimeout(r, 500));

const { instanceId, publishableKey: pk, secretKey: sk } = await seedInstance("Lockout E2E", []);
const api = createBackendClient({ secretKey: sk, apiUrl: AUTH });
let n = 0;
const front = async (path: string, body?: unknown, cookie = "") => {
  const r = await fetch(`${AUTH}/v1/client/${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-publishable-key": pk, origin: AUTH, "x-forwarded-for": `198.51.100.${(++n % 200) + 1}`, ...(cookie ? { cookie } : {}) },
    body: JSON.stringify(body ?? {}),
  });
  return { status: r.status, body: await r.json().catch(() => null), cookie: (r.headers.get("set-cookie") ?? "").split(";")[0] };
};
const mailKey = (to: string) => `devmail:${blindIndex(to, "devmail")}`;
const unlockToken = async (to: string) => {
  const t = await cache().get(mailKey(to));
  const link = t?.match(/https?:\/\/\S+\/unlock\?\S+/)?.[0] ?? "";
  return decodeURIComponent(link.split("#token=")[1] ?? "");
};
// The older per-email sign-in limit (10 per 15 min) would mask lockout here, so reset it between phases.
const resetLimit = async () => { const k = await cache().keys(`rl:${instanceId}:sign_in_acct:*`); if (k.length) await cache().del(...k); };
const hook = await api.webhooks.create({ url: "http://localhost:3990/hook", events: ["user.locked", "user.unlocked"] });

const stamp = Date.now();
const email = `lock.${stamp}@example.com`, password = "a long enough password";
const su = await front("sign_up", { email, password });
const userId = su.body.user.id;
const bad = (e: string) => front("sign_in", { email: e, password: "definitely wrong 1" });

// 1. Five wrong passwords: all plain failures, the sixth is locked, and a correct password is refused while locked.
const codes: string[] = [];
for (let i = 0; i < 5; i++) codes.push((await bad(email)).body.error?.code);
check("first 5 wrong passwords are plain invalid_credentials", codes.every((c) => c === "invalid_credentials"), codes);
const sixth = await bad(email);
check("6th attempt: 429 account_locked", sixth.status === 429 && sixth.body.error?.code === "account_locked", sixth);
const right = await front("sign_in", { email, password });
check("correct password refused while locked", right.status === 429 && right.body.error?.code === "account_locked", right);

// 2. Identical for an account that doesn't exist.
const ghost = `ghost.${stamp}@example.com`;
const gcodes: string[] = [];
for (let i = 0; i < 5; i++) gcodes.push((await bad(ghost)).body.error?.code);
const g6 = await bad(ghost);
check("unknown email: same sequence and same locked response", JSON.stringify(gcodes) === JSON.stringify(codes) && g6.status === sixth.status && JSON.stringify(g6.body) === JSON.stringify(sixth.body), { gcodes, g6 });
check("no database row for an unknown email", (await rows(sql`select count(*)::int c from account_lockouts where instance_id = ${instanceId}`))[0].c === 1);

// 3. State: persisted, HMAC-keyed in Valkey, no raw ids or emails in key names.
const [lk] = await rows(sql`select level, locked_until, unlock_token_hash from account_lockouts where user_id = ${userId}`);
check("persistent state: level 1, locked ~5 min, token hash only", lk.level === 1 && new Date(lk.locked_until).getTime() - Date.now() > 240_000 && /^[0-9a-f]{64}$/.test(lk.unlock_token_hash), lk);
const keys = await cache().keys("lock:*");
check("Valkey keys contain no user id or email", keys.length > 0 && !keys.some((k) => k.includes(userId) || k.includes("example.com")), keys);

// 4. Survives a Valkey flush of the state.
await cache().del(...keys);
const afterFlush = await front("sign_in", { email, password });
check("still locked after Valkey state is lost", afterFlush.body.error?.code === "account_locked", afterFlush);

// 5. Events + email.
await settle();
const ev = await api.auditEvents.list({ type: "user.locked", target: userId });
check("audit user.locked recorded", ev.data.length === 1 && ev.data[0].data?.level === 1, ev.data);
const token = await unlockToken(email);
check("unlock email sent with a link token", token.length > 20);
const dl = await api.webhooks.deliveries(hook.id);
check("webhook user.locked queued", dl.some((d) => d.eventType === "user.locked"), dl);
const got = await api.users.get(userId);
check("backend user shows lockedUntil", !!got.lockedUntil, got);

// 6. Unlock link: wrong token refused, right token works once, level kept.
check("bad unlock token refused", (await front("unlock", { token: "x".repeat(43) })).body.error?.code === "invalid_unlock_link");
check("unlock link works", (await front("unlock", { token })).body.unlocked === true);
check("unlock link is single use", (await front("unlock", { token })).body.error?.code === "invalid_unlock_link");
const ok = await front("sign_in", { email, password });
check("sign-in works after unlocking", ok.body.status === "complete", ok.body);
await settle();
check("audit user.unlocked + webhook", (await api.auditEvents.list({ type: "user.unlocked", target: userId })).data[0]?.data?.reason === "email_link" && (await api.webhooks.deliveries(hook.id)).some((d) => d.eventType === "user.unlocked"));

await resetLimit();
// 7. Progressive: second lock is longer (15 min).
for (let i = 0; i < 5; i++) await bad(email);
const [lk2] = await rows(sql`select level, locked_until from account_lockouts where user_id = ${userId}`);
check("second lock is level 2, ~15 min", lk2.level === 2 && new Date(lk2.locked_until).getTime() - Date.now() > 800_000, lk2);

// 8. Admin unlock resets progression; not-locked unlock is a harmless no-op.
const un = await api.users.unlock(userId);
check("admin unlock returns unlocked:true", un.unlocked === true);
check("admin unlock resets level", (await rows(sql`select level from account_lockouts where user_id = ${userId}`))[0].level === 0);
check("unlocking an unlocked account: unlocked:false", (await api.users.unlock(userId)).unlocked === false);
check("unknown user → 404", await api.users.unlock("user_nope").then(() => false, (e) => e.status === 404));
check("secret key required", (await fetch(`${AUTH}/v1/users/${userId}/unlock`, { method: "POST", headers: { authorization: `Bearer ${pk}` } })).status === 401);
await settle();
check("audit shows developer/api actor", (await api.auditEvents.list({ type: "user.unlocked", target: userId })).data[0]?.actor.type === "api");

// 9. Tenant isolation.
const other = await seedInstance("Lockout E2E (other)", []);
const otherApi = createBackendClient({ secretKey: other.secretKey, apiUrl: AUTH });
check("other instance can't unlock this user", await otherApi.users.unlock(userId).then(() => false, (e) => e.status === 404));

await resetLimit();
// 10. Success doesn't build up failures: 4 wrong + 1 right + 4 wrong stays unlocked.
for (let i = 0; i < 4; i++) await bad(email);
await front("sign_in", { email, password });
const four = [];
for (let i = 0; i < 4; i++) four.push((await bad(email)).body.error?.code);
check("a correct sign-in forgives earlier failures", four.every((c) => c === "invalid_credentials"), four);
await api.users.unlock(userId);

await resetLimit();
// 11. Password reset lifts a lock.
for (let i = 0; i < 6; i++) await bad(email);
check("locked again", (await bad(email)).body.error?.code === "account_locked");
await resetLimit();
await front("password/forgot", { email });
const resetMail = await cache().get(mailKey(email));
const rcode = resetMail?.match(/\b(\d{6})\b/)?.[1] ?? "";
check("reset code mailed even while locked", !!rcode);
const rr = await front("password/reset", { email, code: rcode, password: "another long password" });
check("password reset ok", rr.status === 200, rr.body);
await resetLimit();
check("reset lifted the lock", (await front("sign_in", { email, password: "another long password" })).body.status === "complete");

// 12. Second factor failures count too.
const e2 = `lock2.${stamp}@example.com`;
const s2 = await front("sign_up", { email: e2, password });
const sess = s2.cookie;
const st = await front("mfa/totp", {}, sess);
const secret = st.body.secret as string;
await front("mfa/totp/verify", { code: totpAt(secret, currentCounter()) }, sess);
let locked2 = "";
const tries: string[] = [];
for (let i = 0; i < 8 && !locked2; i++) {
  const pw = await front("sign_in", { email: e2, password });
  if (pw.body.error?.code === "account_locked") { locked2 = "at_password"; break; }
  const r = await front("sign_in/second_factor", { code: "000000" }, pw.cookie);
  tries.push(r.body.error?.code);
  if (r.body.error?.code === "account_locked") locked2 = "at_2fa";
}
check("repeated wrong 2FA codes (even across fresh sign-ins) lock the account", locked2 !== "", tries);
const u2 = (await api.users.list({ limit: 50 })).find((u) => u.emailAddresses[0]?.email === e2);
check("2FA lock visible to admin", !!u2?.lockedUntil);
check("2FA audit event reason", (await (async () => { await settle(); return (await api.auditEvents.list({ type: "user.locked", target: u2!.id })).data[0]?.data?.reason; })()) === "second_factor");
await api.users.unlock(u2!.id);
const pw3 = await front("sign_in", { email: e2, password });
check("after unlock, password + valid code signs in", (await front("sign_in/second_factor", { code: totpAt(secret, currentCounter() + 1) }, pw3.cookie)).body.status === "complete");

await api.webhooks.delete(hook.id);
await closeCache();
await closeDb();
console.log(failures ? `\n${failures} check(s) failed` : "\nAll lockout checks passed");
process.exit(failures ? 1 : 0);
