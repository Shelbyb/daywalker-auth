/**
 * Webhook replay (single + bulk), the dev-instance event stream, and the `daywalker listen` CLI.
 * Needs the service on :3000 started with WEBHOOK_ALLOW_PRIVATE=1 ALLOW_INSECURE_TRANSPORT=1.
 */
import http from "node:http";
import { spawn } from "node:child_process";
import { sql } from "drizzle-orm";
import { seedInstance } from "./seed";
import { db, closeDb } from "../src/lib/db";
import { cache, closeCache } from "../src/lib/cache";
import { createEnvironmentInstance } from "../src/lib/auth/application";
import { verifyWebhook, isWebhookReplay } from "../packages/sdk/src/server";

const AUTH = "http://localhost:3000";
const RECV_PORT = 3991;
let failures = 0;
const check = (name: string, ok: boolean, detail?: unknown) => {
  console.log(`${ok ? "✓" : "✗"} ${name}${ok ? "" : ` — ${JSON.stringify(detail)}`}`);
  if (!ok) failures++;
};
const until = async (fn: () => boolean | Promise<boolean>, ms = 30_000) => {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (await fn()) return true;
    await new Promise((r) => setTimeout(r, 200));
  }
  return false;
};

type Hit = { path: string; body: string; headers: http.IncomingHttpHeaders };
const hits: Hit[] = [];
let respondWith = 200;
const receiver = http.createServer((req, res) => {
  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", () => {
    hits.push({ path: req.url ?? "", body, headers: req.headers });
    if (req.url === "/redir") { res.statusCode = 302; res.setHeader("location", `http://localhost:${RECV_PORT}/redirected`); return res.end(); }
    res.statusCode = respondWith;
    res.end("ok");
  });
}).listen(RECV_PORT);
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const query = async (q: ReturnType<typeof sql>) => (await db().execute(q)) as unknown as Record<string, any>[];
const hitsFor = (path: string) => hits.filter((h) => h.path === path);
const hdrs = (h: Hit) => h.headers as Record<string, string>;

const dev = await seedInstance("Replay E2E", []);
const other = await seedInstance("Replay E2E (other)", []);
const prod = await createEnvironmentInstance(dev.accountId, { name: "Replay E2E", environment: "production", applicationId: dev.applicationId });
const { publishableKey: pk, secretKey: sk } = dev;
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
const deliveries = async (endpointId: string) => (await api(sk, "GET", `webhooks/${endpointId}/deliveries?limit=100`)).body.data as Record<string, any>[]; // eslint-disable-line @typescript-eslint/no-explicit-any

// ---------- Single replay ----------
const ep = await api(sk, "POST", "webhooks", { url: `http://localhost:${RECV_PORT}/hook`, events: ["user.created", "webhook.test"] });
let secret: string = ep.body.secret;
await signUp(`replay.${t}@example.com`);
check("original delivered", await until(() => hitsFor("/hook").some((h) => JSON.parse(h.body).type === "user.created")));
const original = hitsFor("/hook").find((h) => JSON.parse(h.body).type === "user.created")!;
check("original is not marked as a replay", !isWebhookReplay(original.headers as Record<string, string>) && !original.headers["webhook-replay"]);
const origRow = (await deliveries(ep.body.id)).find((d) => d.eventType === "user.created")!;

check("replay needs a secret key", (await api(pk, "POST", `webhooks/deliveries/${origRow.id}/replay`)).status === 401);
check("other tenant can't replay it", (await api(other.secretKey, "POST", `webhooks/deliveries/${origRow.id}/replay`)).status === 404);
check("other tenant can't bulk-replay into it", (await api(other.secretKey, "POST", "webhooks/deliveries/replay", { from: new Date(t - 3600e3), to: new Date(t + 3600e3), endpointId: ep.body.id })).status === 404);
check("unknown delivery is 404", (await api(sk, "POST", "webhooks/deliveries/wd_nope/replay")).status === 404);

// Rotate first: the replay must be signed with the CURRENT secret, not the one the original used.
const oldSecret = secret;
secret = (await api(sk, "POST", `webhooks/${ep.body.id}/rotate_secret`)).body.secret;
const n0 = hitsFor("/hook").length;
const rp = await api(sk, "POST", `webhooks/deliveries/${origRow.id}/replay`);
check("replay accepted (202) and points at the original", rp.status === 202 && rp.body.replayOf === origRow.id && rp.body.status === "pending", rp.body);
check("replay is delivered", await until(() => hitsFor("/hook").length > n0));
const rh = hitsFor("/hook")[n0];
check("replay carries webhook-replay headers", isWebhookReplay(rh.headers as Record<string, string>) && rh.headers["webhook-replay-of"] === origRow.id, rh.headers);
check("replay keeps the original event ID and payload", rh.headers["webhook-id"] === original.headers["webhook-id"] && rh.body === original.body);
let ok = true;
try { verifyWebhook(rh.body, hdrs(rh), secret); } catch { ok = false; }
let oldFails = false;
try { verifyWebhook(rh.body, hdrs(rh), oldSecret); } catch { oldFails = true; }
check("replay is signed with the current secret (and not the old one)", ok && oldFails);
check("replay timestamp is fresh (verifies within the tolerance)", Math.abs(Date.now() / 1000 - Number(rh.headers["webhook-timestamp"])) < 60);
const rows1 = await deliveries(ep.body.id);
check("original row untouched; replay is a separate row", rows1.filter((d) => d.eventType === "user.created").length === 2 && rows1.find((d) => d.id === origRow.id)!.attempts === 1 && !!rows1.find((d) => d.replayOf === origRow.id));
const enc = await query(sql`select payload_enc from webhook_deliveries where replay_of = ${origRow.id}`);
check("replay payload is encrypted at rest", enc[0].payload_enc.startsWith("v1.") && !enc[0].payload_enc.includes("replay."));
const rep2 = await api(sk, "POST", `webhooks/deliveries/${rows1.find((d) => d.replayOf === origRow.id)!.id}/replay`);
check("replaying a replay points at the original, not the replay", rep2.status === 202 && rep2.body.replayOf === origRow.id, rep2.body);
await until(async () => (await deliveries(ep.body.id)).every((d) => d.status !== "pending"));

// A pending replay blocks another one.
respondWith = 500;
const rp3 = await api(sk, "POST", `webhooks/deliveries/${origRow.id}/replay`);
await until(async () => (await deliveries(ep.body.id)).some((d) => d.id === rp3.body.id && d.attempts === 1));
const rp4 = await api(sk, "POST", `webhooks/deliveries/${origRow.id}/replay`);
check("a second replay while one is pending is refused", rp4.status === 409 && rp4.body.error.code === "replay_pending", rp4.body);
respondWith = 200;
await db().execute(sql`update webhook_deliveries set status = 'succeeded' where id = ${rp3.body.id}`);

// ---------- Bulk replay ----------
const marks: string[] = [];
for (let i = 0; i < 3; i++) marks.push((await api(sk, "POST", `webhooks/${ep.body.id}/test`)).body.eventId);
await until(async () => (await deliveries(ep.body.id)).filter((d) => d.eventType === "webhook.test" && d.status === "succeeded").length === 3);
// Make them look failed (as if the receiver had been down).
await db().execute(sql`update webhook_deliveries set status = 'failed', last_error = 'HTTP 500' where event_id in (${sql.join(marks.map((m) => sql`${m}`), sql`, `)})`);
const win = { from: new Date(Date.now() - 3600e3).toISOString(), to: new Date(Date.now() + 60e3).toISOString() };
check("bulk: bad range refused", (await api(sk, "POST", "webhooks/deliveries/replay", { from: win.to, to: win.from })).status === 400);
check("bulk: range over 90 days refused", (await api(sk, "POST", "webhooks/deliveries/replay", { from: new Date(Date.now() - 100 * 86400e3).toISOString(), to: win.to })).status === 400);
check("bulk: garbage dates refused", (await api(sk, "POST", "webhooks/deliveries/replay", { from: "nope", to: win.to })).status === 422);
const hb = hitsFor("/hook").length;
const bulk = await api(sk, "POST", "webhooks/deliveries/replay", win);
check("bulk replays exactly the 3 failed deliveries", bulk.status === 202 && bulk.body.replayed === 3 && bulk.body.truncated === false, bulk.body);
check("bulk replays are delivered and marked", await until(() => hitsFor("/hook").length >= hb + 3) && hitsFor("/hook").slice(hb).every((h) => h.headers["webhook-replay"] === "true"));
await until(async () => (await deliveries(ep.body.id)).every((d) => d.status !== "pending"));
const bulk2 = await api(sk, "POST", "webhooks/deliveries/replay", win);
check("running bulk again replays nothing (already replayed)", bulk2.body.replayed === 0 && bulk2.body.skippedAlreadyReplayed === 3, bulk2.body);
check("bulk: other endpoint filter must exist", (await api(sk, "POST", "webhooks/deliveries/replay", { ...win, endpointId: "we_nope" })).status === 404);

// Disabled endpoints: single replay refused, bulk skips.
await api(sk, "PATCH", `webhooks/${ep.body.id}`, { enabled: false });
check("replay to a disabled endpoint is refused", (await api(sk, "POST", `webhooks/deliveries/${origRow.id}/replay`)).body?.error?.code === "endpoint_disabled");
const bulk3 = await api(sk, "POST", "webhooks/deliveries/replay", win);
check("bulk skips deliveries of disabled endpoints", bulk3.body.replayed === 0 && bulk3.body.skippedDisabled === 3, bulk3.body);
await api(sk, "PATCH", `webhooks/${ep.body.id}`, { enabled: true });

const aud = await query(sql`select type, data_enc from audit_events where instance_id = ${dev.instanceId} and type in ('webhook.delivery_replayed','webhook.bulk_replayed')`);
check("replays are audited (single and bulk)", aud.some((a) => a.type === "webhook.delivery_replayed") && aud.some((a) => a.type === "webhook.bulk_replayed"), aud.map((a) => a.type));

// ---------- Event stream ----------
const readStream = async (key: string, qs = "") => {
  const ac = new AbortController();
  const res = await fetch(`${AUTH}/v1/webhooks/stream${qs}`, { headers: { authorization: `Bearer ${key}` }, signal: ac.signal });
  const state = { res, text: "", ac };
  if (res.ok && res.body) {
    void (async () => {
      const dec = new TextDecoder();
      try { for await (const c of res.body as unknown as AsyncIterable<Uint8Array>) state.text += dec.decode(c, { stream: true }); } catch { /* aborted */ }
    })();
  }
  return state;
};
check("stream needs a secret key", (await fetch(`${AUTH}/v1/webhooks/stream`)).status === 401);
check("stream refuses a publishable key", (await fetch(`${AUTH}/v1/webhooks/stream`, { headers: { authorization: `Bearer ${pk}` } })).status === 401);
const prodRes = await fetch(`${AUTH}/v1/webhooks/stream`, { headers: { authorization: `Bearer ${prod.secretKey}` } });
check("stream refuses production instances", prodRes.status === 403 && (await prodRes.json()).error.code === "development_only");
check("stream rejects unknown event filters", (await fetch(`${AUTH}/v1/webhooks/stream?events=nope`, { headers: { authorization: `Bearer ${sk}` } })).status === 400);

const s1 = await readStream(sk);
check("stream opens as text/event-stream, uncached", s1.res.status === 200 && s1.res.headers.get("content-type")!.startsWith("text/event-stream") && s1.res.headers.get("cache-control")!.includes("no-store"));
check("stream says ready", await until(() => s1.text.includes("event: ready")));
const sub = cache().duplicate();
await sub.subscribe(`whstream:c:${dev.instanceId}`);
const raw: string[] = [];
sub.on("message", (_c, m) => raw.push(m));
const streamEmail = `stream.${t}@example.com`;
await signUp(streamEmail);
check("stream delivers events as they happen", await until(() => s1.text.includes("event: webhook") && s1.text.includes(streamEmail)));
check("events carry the full signed-event body", s1.text.includes('"type":"user.created"'));
check("payloads are encrypted on the Valkey channel", raw.length > 0 && raw.every((m) => m.startsWith("v1.") && !m.includes(streamEmail)), raw[0]?.slice(0, 40));
await sub.quit();

const s2 = await readStream(sk, "?events=session.created");
await until(() => s2.text.includes("event: ready"));
const before2 = s2.text.length;
await signUp(`filter.${t}@example.com`);
await until(() => s2.text.includes("session.created"));
check("event filter: only subscribed types arrive", s2.text.includes('"type":"session.created"') && !s2.text.slice(before2).includes('"type":"user.created"'));

// Concurrency cap: 5 listeners per instance.
const extra = [];
for (let i = 0; i < 3; i++) extra.push(await readStream(sk));
const sixth = await fetch(`${AUTH}/v1/webhooks/stream`, { headers: { authorization: `Bearer ${sk}` } });
check("6th concurrent listener is refused", sixth.status === 429 && (await sixth.json()).error.code === "too_many_streams");
const otherStream = await readStream(other.secretKey);
check("another tenant's stream is independent and sees none of our events", otherStream.res.status === 200);
await signUp(`isolated.${t}@example.com`);
await new Promise((r) => setTimeout(r, 800));
check("events never cross tenants", !otherStream.text.includes("isolated."));
for (const s of [s1, s2, ...extra, otherStream]) s.ac.abort();
check("closing streams frees the listener slots", await until(async () => (await cache().get(`whstream:n:${dev.instanceId}`)) === null || Number(await cache().get(`whstream:n:${dev.instanceId}`)) <= 0, 10_000));
check("no listeners means nothing is published", await (async () => {
  const s = cache().duplicate(); await s.subscribe(`whstream:c:${dev.instanceId}`);
  let got = 0; s.on("message", () => got++);
  await signUp(`nobody.${t}@example.com`); await new Promise((r) => setTimeout(r, 800)); await s.quit();
  return got === 0;
})());

// ---------- CLI ----------
const CLI = "packages/cli/bin/daywalker.mjs";
const runCli = (args: string[], env: Record<string, string>) => {
  const p = spawn("node", [CLI, ...args], { env: { PATH: process.env.PATH!, ...env } as unknown as NodeJS.ProcessEnv, stdio: ["ignore", "pipe", "pipe"] });
  const o = { out: "", err: "", p, code: null as number | null };
  p.stdout.on("data", (d) => (o.out += d));
  p.stderr.on("data", (d) => (o.err += d));
  p.on("exit", (c) => (o.code = c));
  return o;
};
const exited = (o: { code: number | null }) => until(() => o.code !== null, 10_000);

const helpRun = runCli(["--help"], {});
await exited(helpRun);
check("cli --help works", helpRun.code === 0 && helpRun.out.includes("daywalker listen"));
const noKey = runCli(["listen", "--forward-to", `http://localhost:${RECV_PORT}/cli`], {});
await exited(noKey);
check("cli without a key fails clearly", noKey.code === 1 && noKey.err.includes("DAYWALKER_SECRET_KEY"));
const liveKey = runCli(["listen", "--forward-to", `http://localhost:${RECV_PORT}/cli`, "--api-url", AUTH], { DAYWALKER_SECRET_KEY: prod.secretKey });
await exited(liveKey);
check("cli refuses a production key before any request", liveKey.code === 1 && liveKey.err.includes("production") && !liveKey.out.includes("whsec_"), liveKey.err);
const argKey = runCli(["listen", "--key", sk, "--forward-to", `http://localhost:${RECV_PORT}/cli`], {});
await exited(argKey);
check("cli refuses keys on the command line", argKey.code === 1 && argKey.err.includes("DAYWALKER_SECRET_KEY"));
const httpApi = runCli(["listen", "--forward-to", `http://localhost:${RECV_PORT}/cli`, "--api-url", "http://auth.example.com"], { DAYWALKER_SECRET_KEY: sk });
await exited(httpApi);
check("cli refuses plain http to a non-local service", httpApi.code === 1 && httpApi.err.includes("https"));
const badKey = runCli(["listen", "--forward-to", `http://localhost:${RECV_PORT}/cli`, "--api-url", AUTH], { DAYWALKER_SECRET_KEY: "sk_test_" + "x".repeat(40) });
await exited(badKey);
check("cli exits on a rejected key", badKey.code === 1 && badKey.err.includes("rejected"));

const cli = runCli(["listen", "--forward-to", `http://localhost:${RECV_PORT}/cli`, "--api-url", AUTH], { DAYWALKER_SECRET_KEY: sk });
check("cli prints a temporary signing secret and connects", await until(() => cli.out.includes("Connected")) && /whsec_[A-Za-z0-9+/=]{40,}/.test(cli.out), cli.out);
const cliSecret = cli.out.match(/whsec_[A-Za-z0-9+/=]+/)![0];
check("cli secret differs from every endpoint secret", cliSecret !== secret && cliSecret !== oldSecret);
const cliEmail = `cli.${t}@example.com`;
await signUp(cliEmail);
check("cli forwards events to the local server", await until(() => hitsFor("/cli").some((h) => h.body.includes(cliEmail))));
const fh = hitsFor("/cli").find((h) => JSON.parse(h.body).type === "user.created")!;
let cliOk = true, ev;
try { ev = verifyWebhook(fh.body, hdrs(fh), cliSecret); } catch { cliOk = false; }
check("forwarded event verifies with the printed secret (SDK verifyWebhook)", cliOk && ev?.data.email === cliEmail);
let notReal = false;
try { verifyWebhook(fh.body, hdrs(fh), secret); } catch { notReal = true; }
check("forwarded event does NOT verify with a real endpoint secret", notReal);
check("forwarded event is labelled as coming from the cli", fh.headers["webhook-source"] === "cli");
check("cli prints a status line per event, not payloads", cli.out.includes("user.created") && cli.out.includes("200") && !cli.out.includes(cliEmail));
cli.p.kill("SIGINT");
check("cli exits cleanly on SIGINT", await exited(cli) && cli.code === 0, cli.code);

const redir = runCli(["listen", "--forward-to", `http://localhost:${RECV_PORT}/redir`, "--api-url", AUTH, "--events", "user.created"], { DAYWALKER_SECRET_KEY: sk });
await until(() => redir.out.includes("Connected"));
await signUp(`redir.${t}@example.com`);
check("cli does not follow redirects", await until(() => redir.out.includes("302")) && hitsFor("/redirected").length === 0, redir.out);
redir.p.kill("SIGINT");
await exited(redir);

// ---------- Cleanup ----------
await api(sk, "DELETE", `webhooks/${ep.body.id}`);
receiver.close();
await closeDb();
await closeCache();
console.log(failures ? `\n${failures} check(s) failed` : "\nAll webhook replay / stream / CLI checks passed");
process.exit(failures ? 1 : 0);
