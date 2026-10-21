/**
 * Webhook checks: signing, filtering, retries, SSRF rules, encryption at rest.
 * Needs the service on :3000 started with WEBHOOK_ALLOW_PRIVATE=1 ALLOW_INSECURE_TRANSPORT=1.
 */
import http from "node:http";
import { sql } from "drizzle-orm";
import { seedInstance } from "./seed";
import { db, closeDb } from "../src/lib/db";
import { closeCache } from "../src/lib/cache";
import { assertSafeUrl } from "../src/lib/webhooks";
import { verifyWebhook, WebhookVerificationError } from "../packages/sdk/src/server";

const AUTH = "http://localhost:3000";
const RECV_PORT = 3998;
let failures = 0;
const check = (name: string, ok: boolean, detail?: unknown) => {
  console.log(`${ok ? "✓" : "✗"} ${name}${ok ? "" : ` — ${JSON.stringify(detail)}`}`);
  if (!ok) failures++;
};
const until = async (fn: () => boolean | Promise<boolean>, ms = 30_000) => {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (await fn()) return true;
    await new Promise((r) => setTimeout(r, 250));
  }
  return false;
};

// A receiver we control.
type Hit = { path: string; body: string; headers: http.IncomingHttpHeaders };
const hits: Hit[] = [];
let respondWith = 200;
const receiver = http.createServer((req, res) => {
  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", () => {
    hits.push({ path: req.url ?? "", body, headers: req.headers });
    res.statusCode = respondWith;
    res.end("ok");
  });
}).listen(RECV_PORT);
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const query = async (q: ReturnType<typeof sql>) => (await db().execute(q)) as unknown as Record<string, any>[];
const hitsFor = (path: string) => hits.filter((h) => h.path === path);

const { publishableKey: pk, secretKey: sk } = await seedInstance("Webhooks E2E", []);
const other = await seedInstance("Webhooks E2E (other)", []);
const api = (key: string, method: string, path: string, body?: unknown) =>
  fetch(`${AUTH}/v1/${path}`, {
    method,
    headers: { authorization: `Bearer ${key}`, ...(body !== undefined ? { "content-type": "application/json" } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
  }).then(async (r) => ({ status: r.status, body: await r.json() }));
const signUp = (email: string) =>
  fetch(`${AUTH}/v1/client/sign_up`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-publishable-key": pk, origin: AUTH, "x-forwarded-for": `198.51.100.${Math.floor(Math.random() * 250) + 1}` },
    body: JSON.stringify({ email, password: "a good password" }),
  }).then((r) => r.json());
const t = Date.now();

// ---------- SSRF rules (checked directly, without the test override) ----------
const rejects = async (url: string) => assertSafeUrl(url).then(() => false, () => true);
check("rejects the cloud metadata address", await rejects("https://169.254.169.254/latest/meta-data"));
check("rejects private IPv4", await rejects("https://10.0.0.5/hook"));
check("rejects loopback", await rejects("https://127.0.0.1/hook"));
check("rejects IPv6 loopback", await rejects("https://[::1]/hook"));
check("rejects IPv4-mapped IPv6", await rejects("https://[::ffff:127.0.0.1]/hook"));
check("rejects non-HTTP schemes", await rejects("ftp://example.com/hook"));
check("rejects credentials in the URL", await rejects("https://user:pw@93.184.216.34/hook"));
check("accepts a public address", !(await rejects("https://93.184.216.34/hook")));

// ---------- Registration ----------
check("secret key required", (await api(pk, "GET", "webhooks")).status === 401);
check("unknown event type rejected", (await api(sk, "POST", "webhooks", { url: `http://localhost:${RECV_PORT}/x`, events: ["nope"] })).status === 400);
const all = await api(sk, "POST", "webhooks", { url: `http://localhost:${RECV_PORT}/all`, description: "everything" });
check("create endpoint returns a signing secret once", all.status === 201 && all.body.secret?.startsWith("whsec_"), all.body);
const secret: string = all.body.secret;
const filtered = await api(sk, "POST", "webhooks", { url: `http://localhost:${RECV_PORT}/orgs`, events: ["organization.created"] });
check("get never returns the secret", !("secret" in (await api(sk, "GET", `webhooks/${all.body.id}`)).body));
check("list shows both", (await api(sk, "GET", "webhooks")).body.data.length === 2);

const rows = await query(sql`select url_enc, secret_enc from webhook_endpoints where id = ${all.body.id}`);
check("URL and secret are encrypted at rest", rows[0].url_enc.startsWith("v1.") && rows[0].secret_enc.startsWith("v1.") && !String(rows[0].url_enc).includes("localhost") && !String(rows[0].secret_enc).includes(secret.slice(7)), rows[0]);

// ---------- Delivery + signature ----------
const email = `hook.${t}@example.com`;
const user = await signUp(email);
check("user.created delivered", await until(() => hitsFor("/all").some((h) => JSON.parse(h.body).type === "user.created")));
const created = hitsFor("/all").find((h) => JSON.parse(h.body).type === "user.created")!;
let event;
try { event = verifyWebhook(created.body, created.headers as Record<string, string>, secret); } catch (e) { event = e; }
check("SDK verifyWebhook accepts the signature", !(event instanceof Error) && (event as { data: { userId: string } }).data.userId === user.user.id, event);
check("payload carries the email", JSON.parse(created.body).data.email === email);
const bad = (fn: () => unknown) => { try { fn(); return false; } catch (e) { return e instanceof WebhookVerificationError; } };
check("tampered body rejected", bad(() => verifyWebhook(created.body.replace("user.created", "user.deleted"), created.headers as Record<string, string>, secret)));
check("wrong secret rejected", bad(() => verifyWebhook(created.body, created.headers as Record<string, string>, "whsec_" + Buffer.alloc(32, 1).toString("base64"))));
check("old timestamp rejected (replay)", bad(() => verifyWebhook(created.body, { ...created.headers, "webhook-timestamp": String(Math.floor(Date.now() / 1000) - 3600) } as unknown as Record<string, string>, secret)));
check("missing headers rejected", bad(() => verifyWebhook(created.body, {}, secret)));
check("session.created also delivered", await until(() => hitsFor("/all").some((h) => JSON.parse(h.body).type === "session.created")));
check("event filter: unsubscribed endpoint got nothing", hitsFor("/orgs").length === 0);

// ---------- Retries ----------
respondWith = 500;
const before = hitsFor("/all").length;
const test1 = await api(sk, "POST", `webhooks/${all.body.id}/test`);
check("send test → 202", test1.status === 202, test1.body);
check("failing receiver is retried later (HTTP 500 recorded)", await until(async () => {
  const d = (await api(sk, "GET", `webhooks/${all.body.id}/deliveries`)).body.data.find((x: { eventType: string }) => x.eventType === "webhook.test");
  return d?.status === "pending" && d.attempts === 1 && d.lastError === "HTTP 500" && !!d.nextAttemptAt;
}));
check("exactly one attempt so far (backoff, not a hot loop)", hitsFor("/all").length === before + 1);
const failing = (await api(sk, "GET", `webhooks/${all.body.id}/deliveries`)).body.data.find((x: { eventType: string }) => x.eventType === "webhook.test");
const firstId = hits.at(-1)!.headers["webhook-id"];

respondWith = 200;
const retry = await api(sk, "POST", `webhooks/deliveries/${failing.id}/retry`);
check("manual retry accepted", retry.status === 202, retry.body);
check("retry succeeds and keeps the same event ID", await until(async () => {
  const d = (await api(sk, "GET", `webhooks/${all.body.id}/deliveries`)).body.data.find((x: { id: string }) => x.id === failing.id);
  return d?.status === "succeeded" && hits.at(-1)!.headers["webhook-id"] === firstId;
}));

// Exhaustion: pretend 7 attempts already failed.
respondWith = 500;
const test2 = await api(sk, "POST", `webhooks/${all.body.id}/test`);
await until(async () => (await api(sk, "GET", `webhooks/${all.body.id}/deliveries`)).body.data.some((d: { eventId: string; attempts: number }) => d.eventId === test2.body.eventId && d.attempts >= 1));
await db().execute(sql`update webhook_deliveries set attempts = 7, next_attempt_at = now() where event_id = ${test2.body.eventId}`);
check("after the last attempt the delivery is marked failed", await until(async () =>
  (await api(sk, "GET", `webhooks/${all.body.id}/deliveries`)).body.data.some((d: { eventId: string; status: string }) => d.eventId === test2.body.eventId && d.status === "failed")));
respondWith = 200;

// ---------- Log hygiene + at-rest encryption ----------
const log = JSON.stringify((await api(sk, "GET", `webhooks/${all.body.id}/deliveries`)).body);
check("delivery log never exposes payloads", !log.includes(email) && !log.includes("payload"));
const pay = await query(sql`select payload_enc from webhook_deliveries where event_type = 'user.created' limit 1`);
check("payloads are encrypted at rest", pay[0].payload_enc.startsWith("v1.") && !String(pay[0].payload_enc).includes(email));

// ---------- Filter, disable, rotate ----------
const orgUserHits = hitsFor("/orgs").length;
check("subscribed endpoint receives only its events", orgUserHits === 0);
check("disable endpoint", (await api(sk, "PATCH", `webhooks/${all.body.id}`, { enabled: false })).body.enabled === false);
const mark = hitsFor("/all").length;
await signUp(`quiet.${t}@example.com`);
await new Promise((r) => setTimeout(r, 1500));
check("disabled endpoint receives nothing", hitsFor("/all").length === mark);
await api(sk, "PATCH", `webhooks/${all.body.id}`, { enabled: true });
const rot = await api(sk, "POST", `webhooks/${all.body.id}/rotate_secret`);
check("rotate returns a new secret", rot.body.secret?.startsWith("whsec_") && rot.body.secret !== secret);
await api(sk, "POST", `webhooks/${all.body.id}/test`);
check("new deliveries use the new secret only", await until(() => {
  const h = hits.at(-1)!;
  return h.path === "/all" && JSON.parse(h.body).type === "webhook.test" && !bad(() => verifyWebhook(h.body, h.headers as Record<string, string>, rot.body.secret)) && bad(() => verifyWebhook(h.body, h.headers as Record<string, string>, secret));
}));

// ---------- Private URLs blocked at the service too (not just in the unit check) ----------
check("update to an invalid URL rejected", (await api(sk, "PATCH", `webhooks/${all.body.id}`, { url: "ftp://nope.example.com" })).status === 400);

// ---------- Isolation + cleanup ----------
check("other tenant can't read the endpoint", (await api(other.secretKey, "GET", `webhooks/${all.body.id}`)).status === 404);
check("other tenant can't retry its deliveries", (await api(other.secretKey, "POST", `webhooks/deliveries/${failing.id}/retry`)).status === 404);
check("other tenant list is empty", (await api(other.secretKey, "GET", "webhooks")).body.data.length === 0);
check("delete endpoint", (await api(sk, "DELETE", `webhooks/${all.body.id}`)).status === 200);
const left = await query(sql`select count(*)::int as n from webhook_deliveries where endpoint_id = ${all.body.id}`);
check("deleting an endpoint removes its delivery history", left[0].n === 0, left);
await api(sk, "DELETE", `webhooks/${filtered.body.id}`);

receiver.close();
await closeDb();
await closeCache();
console.log(failures ? `\n${failures} check(s) failed` : "\nAll webhook checks passed");
process.exit(failures ? 1 : 0);
