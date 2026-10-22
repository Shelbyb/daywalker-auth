/** Audit logs: events are recorded, filterable, paged, tenant-isolated, encrypted, and purged after 90 days. */
import { sql } from "drizzle-orm";
import { seedInstance } from "./seed";
import { db, closeDb } from "../src/lib/db";
import { closeCache } from "../src/lib/cache";
import { purgeAudit } from "../src/lib/audit";
import { auditFor } from "../src/lib/dashboard";
import { createBackendClient } from "../packages/sdk/src/server";

const AUTH = "http://localhost:3000";
let failures = 0;
const check = (name: string, ok: boolean, detail?: unknown) => {
  console.log(`${ok ? "✓" : "✗"} ${name}${ok ? "" : ` — ${JSON.stringify(detail)?.slice(0, 400)}`}`);
  if (!ok) failures++;
};
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const rows = async (q: ReturnType<typeof sql>) => (await db().execute(q)) as unknown as Record<string, any>[];
const settle = () => new Promise((r) => setTimeout(r, 400)); // records are written off the request path

const { instanceId, publishableKey: pk, secretKey: sk } = await seedInstance("Audit E2E", []);
const other = await seedInstance("Audit E2E (other)", []);
const ip = `198.51.100.${Math.floor(Math.random() * 250) + 1}`;
let cookie = "";
const front = async (path: string, body?: unknown, method = "POST") => {
  const r = await fetch(`${AUTH}/v1/client/${path}`, {
    method,
    headers: { "content-type": "application/json", "x-publishable-key": pk, origin: AUTH, "x-forwarded-for": ip, "user-agent": "AuditTest/1.0", ...(cookie ? { cookie } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const sc = r.headers.get("set-cookie");
  if (sc) cookie = sc.split(";")[0];
  return { status: r.status, body: await r.json().catch(() => null) };
};
const api = createBackendClient({ secretKey: sk, apiUrl: AUTH });

const email = `audit.${Date.now()}@example.com`, password = "a long enough password";
const su = await front("sign_up", { email, password });
const userId = su.body.user.id;
cookie = "";
await front("sign_in", { email, password: "wrong password!!" });
await front("sign_in", { email: `nobody.${Date.now()}@example.com`, password: "whatever password" });
await front("sign_in", { email, password });
await front("session", undefined, "DELETE");
await fetch(`${AUTH}/v1/instance/signing_keys/rotate`, { method: "POST", headers: { authorization: `Bearer ${sk}` } });
const hook = await api.webhooks.create({ url: "https://example.com/hook" });
await api.webhooks.delete(hook.id);
await settle();

const all = await api.auditEvents.list({ limit: 200 });
const types = all.data.map((e) => e.type);
check("sign-up is logged", types.includes("user.signed_up"));
check("a wrong password on a real account is logged", all.data.some((e) => e.type === "user.sign_in_failed" && e.target === userId));
check("an unknown email is NOT logged (no noise from scanners)", all.data.filter((e) => e.type === "user.sign_in_failed").length === 1);
const signin = all.data.find((e) => e.type === "user.signed_in" && e.data?.ip === ip);
check("sign-in is logged with IP and browser", !!signin && signin.data?.userAgent === "AuditTest/1.0" && signin.actor.type === "user", signin);
check("sign-out is logged", types.includes("user.signed_out"));
check("signing-key rotation by API is logged with actor api", all.data.some((e) => e.type === "signing_key.rotated" && e.actor.type === "api"));
check("webhook create and delete are logged", types.includes("webhook.created") && types.includes("webhook.deleted"));
check("newest first", all.data.every((e, i, a) => i === 0 || new Date(a[i - 1].createdAt) >= new Date(e.createdAt)));

const failed = await api.auditEvents.list({ type: "user.sign_in_failed" });
check("filter by type", failed.data.length === 1 && failed.data[0].type === "user.sign_in_failed");
const byUser = await api.auditEvents.list({ target: userId });
check("filter by target", byUser.data.length >= 4 && byUser.data.every((e) => e.target === userId));

const p1 = await api.auditEvents.list({ limit: 2 });
const p2 = await api.auditEvents.list({ limit: 2, before: p1.nextCursor! });
check("cursor paging returns the next, non-overlapping page", p1.data.length === 2 && !!p1.nextCursor && p2.data.length === 2 && !p2.data.some((e) => p1.data.some((x) => x.id === e.id)));
check("a page that ends has no cursor", (await api.auditEvents.list({ limit: 200 })).nextCursor === null);

// Security
check("needs a secret key (publishable key → 401)", (await fetch(`${AUTH}/v1/audit_events`, { headers: { authorization: `Bearer ${pk}` } })).status === 401);
check("no key → 401", (await fetch(`${AUTH}/v1/audit_events`)).status === 401);
const otherList = await createBackendClient({ secretKey: other.secretKey, apiUrl: AUTH }).auditEvents.list({ limit: 200 });
check("another instance can't see these events", otherList.data.length === 0);
check("another instance's cursor can't be used to peek", (await createBackendClient({ secretKey: other.secretKey, apiUrl: AUTH }).auditEvents.list({ before: p1.data[0].id })).data.length === 0);
const raw = await rows(sql`select data_enc from audit_events where instance_id = ${instanceId} and data_enc is not null`);
check("details are encrypted at rest (no IP or browser in plaintext)", raw.length > 0 && raw.every((r) => String(r.data_enc).startsWith("v1.") && !String(r.data_enc).includes(ip) && !String(r.data_enc).includes("AuditTest")));
check("no emails or passwords are stored anywhere in the log", !JSON.stringify(await rows(sql`select * from audit_events where instance_id = ${instanceId}`)).includes(email) && !JSON.stringify(all).includes(password));
let denied = false;
try {
  await auditFor("user_not_an_owner", instanceId, {});
} catch (e) {
  denied = (e as { status?: number }).status === 404;
}
check("dashboard: a developer who doesn't own the instance gets 404", denied);

// Retention
await db().execute(sql`update audit_events set created_at = now() - interval '91 days' where instance_id = ${instanceId} and type = 'user.signed_up'`);
await purgeAudit();
const left = await api.auditEvents.list({ limit: 200 });
check("events older than 90 days are purged, newer ones kept", !left.data.some((e) => e.type === "user.signed_up") && left.data.length === all.data.length - 1);

await closeDb();
await closeCache();
console.log(failures ? `\n${failures} check(s) failed` : "\nAll audit log checks passed");
process.exit(failures ? 1 : 0);
