/** Self-service account deletion and data export: re-auth, grace period, cancel, purge, export contents, limits, audit. */
import { sql } from "drizzle-orm";
import { seedInstance } from "./seed";
import { db, closeDb } from "../src/lib/db";
import { cache, closeCache } from "../src/lib/cache";
import { blindIndex } from "../src/lib/crypto";
import { totpAt, currentCounter } from "../src/lib/auth/totp";
import { purgeDueDeletions } from "../src/lib/auth/account-deletion";
import { createBackendClient } from "../packages/sdk/src/server";

const AUTH = "http://localhost:3000";
let failures = 0;
const check = (name: string, ok: boolean, detail?: unknown) => {
  console.log(`${ok ? "✓" : "✗"} ${name}${ok ? "" : ` — ${JSON.stringify(detail)?.slice(0, 400)}`}`);
  if (!ok) failures++;
};
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const rows = async (q: ReturnType<typeof sql>) => (await db().execute(q)) as unknown as Record<string, any>[];

const { instanceId, publishableKey: pk, secretKey: sk } = await seedInstance("Deletion E2E", []);
const api = createBackendClient({ secretKey: sk, apiUrl: AUTH });
let n = 0;
const front = async (path: string, body?: unknown, cookie = "", method = "POST") => {
  const r = await fetch(`${AUTH}/v1/client/${path}`, {
    method,
    headers: { "content-type": "application/json", "x-publishable-key": pk, origin: AUTH, "x-forwarded-for": `203.0.113.${(++n % 200) + 1}`, ...(cookie ? { cookie } : {}) },
    body: method === "GET" ? undefined : JSON.stringify(body ?? {}),
  });
  return { status: r.status, body: await r.json().catch(() => null), cookie: (r.headers.get("set-cookie") ?? "").split(";")[0], headers: r.headers };
};
const mail = async (to: string) => (await cache().get(`devmail:${blindIndex(to, "devmail")}`)) ?? "";
const resetLimit = async () => { const k = await cache().keys(`rl:${instanceId}:*`); if (k.length) await cache().del(...k); };
const password = "a long enough password";
const stamp = Date.now();
const mk = async (tag: string) => {
  const email = `${tag}.${stamp}@example.com`;
  const su = await front("sign_up", { email, password, firstName: "Ada", lastName: "Lovelace" });
  return { email, id: su.body.user.id as string, cookie: su.cookie };
};

// Settings API
check("default: enabled, 14 days", JSON.stringify(await api.accountDeletion.get()) === JSON.stringify({ enabled: true, graceDays: 14 }));
const bad = await fetch(`${AUTH}/v1/instance/account_deletion`, { method: "PATCH", headers: { authorization: `Bearer ${sk}`, "content-type": "application/json" }, body: JSON.stringify({ graceDays: 500 }) });
check("grace over 90 days rejected", bad.status === 422, bad.status);

// 1. Delete requires the password.
const u = await mk("del");
const needs = await front("me/reauth_code", undefined, u.cookie, "GET");
check("requirements: password only", needs.body.password === true && needs.body.twoFactor === false && needs.body.emailCode === false, needs.body);
const noPw = await front("me/delete", {}, u.cookie);
check("no password: refused", noPw.status === 400 && noPw.body.error?.code === "credentials_required", noPw);
const wrong = await front("me/delete", { password: "wrong password 12" }, u.cookie);
check("wrong password: refused", wrong.status === 400 && wrong.body.error?.code === "invalid_credentials", wrong);
check("still signed in and not scheduled", (await front("session", undefined, u.cookie, "GET")).body.user?.id === u.id);
const unauth = await front("me/delete", { password });
check("no session: 401", unauth.status === 401, unauth);

// 2. Export needs re-auth, decrypts, hides secrets, is audited.
const noEx = await front("me/export", {}, u.cookie);
check("export without re-auth refused", noEx.status === 400, noEx);
const ex = await front("me/export", { password }, u.cookie);
const text = JSON.stringify(ex.body);
check("export ok, no-store, attachment", ex.status === 200 && ex.headers.get("cache-control") === "no-store" && (ex.headers.get("content-disposition") ?? "").includes("attachment"), ex.headers);
check("export has decrypted email and name", ex.body.emailAddresses?.[0]?.email === u.email && ex.body.profile?.firstName === "Ada" && ex.body.profile?.lastName === "Lovelace", ex.body?.profile);
check("export lists sessions with device info", Array.isArray(ex.body.sessions) && ex.body.sessions.length >= 1);
check("export has no secrets or hashes", !/argon2|\$2[aby]\$|refreshTokenHash|passwordHash|"secret"|totpSecret/i.test(text) && ex.body.password?.set === true && !("hash" in (ex.body.password ?? {})), Object.keys(ex.body));
const auditEx = await rows(sql`select count(*)::int c from audit_events where instance_id = ${instanceId} and type = 'user.data_exported' and target_id = ${u.id}`);
check("export audited", auditEx[0].c === 1, auditEx);
await resetLimit();
let limited = 0;
for (let i = 0; i < 4; i++) if ((await front("me/export", { password }, u.cookie)).status === 429) limited++;
check("export rate limited (3/hour)", limited >= 1, limited);
await resetLimit();

// 3. Delete: scheduled, signed out everywhere, mail with cancel link, webhook-ish audit.
const second = await front("sign_in", { email: u.email, password });
const hook = await api.webhooks.create({ url: "http://localhost:3990/hook", events: ["user.deleted", "user.deletion_requested", "user.deletion_canceled"] });
void hook;
const del = await front("me/delete", { password }, u.cookie);
check("delete: scheduled in ~14 days", del.status === 200 && del.body.deleted === false && Math.abs(Date.parse(del.body.scheduledFor) - (Date.now() + 14 * 86_400_000)) < 120_000, del);
check("session cookie cleared", /max-age=0|expires=/i.test(del.headers.get("set-cookie") ?? ""), del.headers.get("set-cookie"));
check("this session is gone", (await front("session", undefined, u.cookie, "GET")).body.user === null);
check("other session is gone", (await front("session", undefined, second.cookie, "GET")).body.user === null);
const m = await mail(u.email);
const link = m.match(/https?:\/\/\S+\/cancel-deletion\?\S+/)?.[0] ?? "";
const token = decodeURIComponent(link.split("#token=")[1] ?? "");
check("email has cancel link with token in the fragment", token.length > 20 && !link.split("#")[0].includes(token), link);
const row = (await rows(sql`select deletion_token_hash h, deletion_scheduled_at s from users where id = ${u.id}`))[0];
check("only the token hash is stored", row.h && row.h !== token && row.h.length === 64 && !!row.s, row);
const blocked = await front("sign_in", { email: u.email, password });
check("sign-in refused while pending", blocked.status === 403 && blocked.body.error?.code === "account_pending_deletion", blocked);
const again = await front("sign_in", { email: u.email, password: "wrong password 12" });
check("wrong password still just invalid_credentials (no leak)", again.body.error?.code === "invalid_credentials", again);
const bu = await api.users.get(u.id);
check("backend user still exists", bu.id === u.id);

// 4. Cancel with the link: single use, then sign in works.
const badTok = await front("cancel_deletion", { token: "x".repeat(40) });
check("bad cancel token refused", badTok.status === 400 && badTok.body.error?.code === "invalid_cancel_link", badTok);
const okc = await front("cancel_deletion", { token });
check("cancel link works", okc.status === 200 && okc.body.canceled === true, okc);
check("cancel link is single use", (await front("cancel_deletion", { token })).status === 400);
const back = await front("sign_in", { email: u.email, password });
check("sign-in works again", back.status === 200 && back.body.status === "complete", back);
const aud = await rows(sql`select type from audit_events where instance_id = ${instanceId} and target_id = ${u.id} and type like 'user.deletion%'`);
check("requested + canceled audited", aud.some((r) => r.type === "user.deletion_requested") && aud.some((r) => r.type === "user.deletion_canceled"), aud);

// 5. Backend cancel.
const d2 = await front("me/delete", { password }, back.cookie);
check("scheduled again", d2.status === 200);
const bc = await api.users.cancelDeletion(u.id);
check("backend cancel: canceled", bc.canceled === true, bc);
check("backend cancel again: false", (await api.users.cancelDeletion(u.id)).canceled === false);

// 6. Purge: after the grace period the user and their data go; org they were alone in goes too.
const s3 = await front("sign_in", { email: u.email, password });
const org = await front("organizations", { name: "Solo Org" }, s3.cookie);
check("created org", org.status < 300, org);
const d3 = await front("me/delete", { password }, s3.cookie);
check("sole member: delete allowed", d3.status === 200, d3);
await db().execute(sql`update users set deletion_scheduled_at = now() - interval '1 minute' where id = ${u.id}`);
const purged = await purgeDueDeletions();
check("purge job deleted the user", purged >= 1, purged);
check("user is gone", (await rows(sql`select 1 from users where id = ${u.id}`)).length === 0);
check("emails gone", (await rows(sql`select 1 from email_addresses where user_id = ${u.id}`)).length === 0);
check("solo org gone", (await rows(sql`select 1 from organizations where instance_id = ${instanceId} and name = 'Solo Org'`)).length === 0);
const left = await rows(sql`select data_enc from audit_events where instance_id = ${instanceId} and target_id = ${u.id} and type = 'user.signed_in'`);
check("audit trail kept without details", left.length > 0 && left.every((r) => r.data_enc === null), left.length);
check("sign-in no longer works", (await front("sign_in", { email: u.email, password })).body.error?.code === "invalid_credentials");

// 7. Sole admin of a shared organization is blocked.
const a = await mk("admin"), b = await mk("member");
const o = await front("organizations", { name: "Team" }, a.cookie);
const orgId = o.body.organization?.id ?? o.body.id;
await db().execute(sql`insert into memberships (org_id, user_id, role) values (${orgId}, ${b.id}, 'member')`);
const blockedAdmin = await front("me/delete", { password }, a.cookie);
check("sole admin of a shared org blocked", blockedAdmin.status === 409 && blockedAdmin.body.error?.code === "sole_org_admin", blockedAdmin);

// 8. Two-factor accounts need a code.
const t = await mk("tfa");
const st = await front("mfa/totp", {}, t.cookie);
await front("mfa/totp/verify", { code: totpAt(st.body.secret, currentCounter()) }, t.cookie);
const tn = await front("me/reauth_code", undefined, t.cookie, "GET");
check("requirements: password + 2FA", tn.body.password && tn.body.twoFactor, tn.body);
const noCode = await front("me/delete", { password }, t.cookie);
check("2FA account: code required", noCode.status === 400 && noCode.body.error?.code === "credentials_required", noCode);
const wrongCode = await front("me/export", { password, code: "000000" }, t.cookie);
check("wrong 2FA code refused", wrongCode.status === 400 && wrongCode.body.error?.code === "invalid_code", wrongCode);
const goodCode = await front("me/export", { password, code: totpAt(st.body.secret, currentCounter() + 1) }, t.cookie);
check("right 2FA code: export ok", goodCode.status === 200 && goodCode.body.twoFactor?.authenticatorApp?.enabled === true && !JSON.stringify(goodCode.body).includes(st.body.secret), goodCode.status);

// 9. Passwordless accounts confirm by emailed code.
const p = await mk("nopw");
await db().execute(sql`delete from passwords where user_id = ${p.id}`);
const pn = await front("me/reauth_code", undefined, p.cookie, "GET");
check("requirements: email code", pn.body.emailCode === true && !pn.body.password, pn.body);
const noMail = await front("me/delete", {}, p.cookie);
check("no code: refused", noMail.status === 400, noMail);
const sent = await front("me/reauth_code", {}, p.cookie);
check("code emailed", sent.status === 200);
const code = (await mail(p.email)).match(/\b(\d{6})\b/)?.[1] ?? "";
check("wrong emailed code refused", (await front("me/delete", { emailCode: code === "123456" ? "654321" : "123456" }, p.cookie)).status === 400);
const pd = await front("me/delete", { emailCode: code }, p.cookie);
check("right emailed code: scheduled", pd.status === 200 && pd.body.deleted === false, pd);
const pf = await front("me/reauth_code", {}, t.cookie);
check("email code not offered to accounts with a password", pf.status === 400, pf);

// 10. Grace period 0 deletes at once; disabled blocks.
await api.accountDeletion.update({ graceDays: 0 });
const z = await mk("zero");
const zd = await front("me/delete", { password }, z.cookie);
check("grace 0: deleted immediately", zd.status === 200 && zd.body.deleted === true, zd);
check("grace 0: user gone", (await rows(sql`select 1 from users where id = ${z.id}`)).length === 0);
await api.accountDeletion.update({ enabled: false, graceDays: 14 });
const off = await mk("off");
const od = await front("me/delete", { password }, off.cookie);
check("disabled: refused", od.status === 403 && od.body.error?.code === "account_deletion_disabled", od);
await api.accountDeletion.update({ enabled: true });

// 11. Hosted cancel page renders.
const page = await fetch(`${AUTH}/cancel-deletion?pk=${pk}`);
check("hosted cancel page renders", page.status === 200 && (await page.text()).includes("Keep"), page.status);

await closeDb();
await closeCache();
console.log(failures ? `\n${failures} check(s) failed` : "\nAll checks passed");
process.exit(failures ? 1 : 0);
