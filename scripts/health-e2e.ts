/**
 * Public health: GET /v1/health and the /status page. Checks the shape (nothing but ok/degraded/down per component),
 * that nothing sensitive leaks, the job-runner heartbeat, and the abuse guard. Needs the service on :3000.
 */
import { cache, closeCache } from "../src/lib/cache";

const AUTH = "http://localhost:3000";
let failures = 0;
const check = (name: string, ok: boolean, detail?: unknown) => {
  console.log(`${ok ? "✓" : "✗"} ${name}${ok ? "" : ` — ${JSON.stringify(detail)}`}`);
  if (!ok) failures++;
};
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const until = async (fn: () => boolean | Promise<boolean>, ms = 30_000) => {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (await fn()) return true;
    await sleep(500);
  }
  return false;
};
const health = (headers: Record<string, string> = {}) => fetch(`${AUTH}/v1/health`, { headers }).then(async (r) => ({ r, text: await r.text() }));
const LEVELS = ["ok", "degraded", "down"];
const COMPONENTS = ["database", "valkey", "email", "jobs", "signingKeys"];

// The job runner beats every 15 s; wait for the first one after a (re)start.
check("job runner heartbeat appears", await until(async () => (await cache().get("health:jobs:heartbeat")) !== null, 30_000));
await sleep(5500); // /v1/health shares one result for 5 s

const { r, text } = await health();
const body = JSON.parse(text);
check("GET /v1/health needs no credentials and is 200", r.status === 200, r.status);
check("overall status is ok on a healthy service", body.status === "ok", body);
check("exactly status, components and checkedAt are returned", Object.keys(body).sort().join() === "checkedAt,components,status", Object.keys(body));
check("exactly the five components, each ok/degraded/down", Object.keys(body.components).sort().join() === [...COMPONENTS].sort().join() && Object.values(body.components).every((v) => LEVELS.includes(v as string)), body.components);
check("database, valkey, email, jobs and signing keys are ok", COMPONENTS.every((c) => body.components[c] === "ok"), body.components);
check("checkedAt is a recent ISO time", Math.abs(Date.now() - Date.parse(body.checkedAt)) < 60_000);
check("never cached", r.headers.get("cache-control")?.includes("no-store") === true);

// Nothing sensitive may appear: connection strings, hosts, keys, the master key, versions, instance IDs.
const secrets = [process.env.DATABASE_URL, process.env.VALKEY_URL, process.env.MASTER_KEY, process.env.RESEND_API_KEY, process.env.TWILIO_AUTH_TOKEN, "localhost", "postgres", "5432", "6379", "ins_", "pk_", "sk_", "resend", "twilio", "next", "v16"].filter(Boolean) as string[];
check("response leaks no configuration, hosts, keys or IDs", secrets.every((s) => !text.toLowerCase().includes(s.toLowerCase())), secrets.filter((s) => text.toLowerCase().includes(s.toLowerCase())));
check("no cookies are set", !r.headers.has("set-cookie"));
check("a bogus Authorization header changes nothing", (await health({ authorization: "Bearer sk_test_nope" })).r.status === 200);
check("POST is not allowed", (await fetch(`${AUTH}/v1/health`, { method: "POST" })).status === 405);
check("/healthz stays minimal", (await fetch(`${AUTH}/healthz`).then((x) => x.text())) === '{"ok":true}');

// ---------- Status page ----------
const page = await fetch(`${AUTH}/status`);
const html = await page.text();
check("/status is public", page.status === 200 && html.includes("All systems operational"), page.status);
check("/status lists every component as operational", ["Database", "Cache and rate limits", "Email delivery", "Background jobs", "Token signing"].every((l) => html.includes(l)) && !html.includes("Outage") && !html.includes("Degraded"));
check("/status leaks nothing either", secrets.filter((s) => s.length > 5 && !["localhost", "postgres", "next", "resend", "twilio", "ins_", "pk_", "sk_"].includes(s)).every((s) => !html.includes(s)));
check("/status has a CSP and refuses framing", !!page.headers.get("content-security-policy")?.includes("frame-ancestors 'none'") && page.headers.get("x-frame-options") === "DENY");
check("/status is linked from the home page", (await fetch(`${AUTH}/`).then((x) => x.text())).includes('href="/status"'));

// ---------- Degraded when the job runner stops beating ----------
await cache().del("health:jobs:heartbeat");
await sleep(5500);
const stale = await health();
const sb = JSON.parse(stale.text);
check("no heartbeat => jobs degraded, overall degraded, still HTTP 200", stale.r.status === 200 && sb.components.jobs === "degraded" && sb.status === "degraded" && sb.components.database === "ok", sb);
const sp = await fetch(`${AUTH}/status`).then((x) => x.text());
check("/status shows the degraded state", sp.includes("Some systems are degraded"));
// The real loop may overwrite our stale value between writing it and the (5 s shared) read, so allow a few tries.
let sawStale = false;
for (let i = 0; i < 4 && !sawStale; i++) {
  await cache().set("health:jobs:heartbeat", String(Date.now() - 5 * 60_000), "EX", 60);
  await sleep(5200);
  sawStale = JSON.parse((await health()).text).components.jobs === "degraded";
}
check("a stale heartbeat (5 min old) is also degraded", sawStale);
check("the running job loop restores it within a tick", await until(async () => { await sleep(5500); return JSON.parse((await health()).text).status === "ok"; }, 40_000));

// ---------- Abuse guard ----------
const ip = `203.0.113.${Math.floor(Math.random() * 200) + 1}`;
let limited = 0;
for (let i = 0; i < 130; i++) if ((await health({ "x-forwarded-for": ip })).r.status === 429) limited++;
check("one client is rate limited after 120 requests a minute", limited >= 5, limited);
check("another client is unaffected", (await health({ "x-forwarded-for": "198.51.100.77" })).r.status === 200);

await closeCache();
console.log(failures ? `\n${failures} check(s) failed` : "\nAll health checks passed");
process.exit(failures ? 1 : 0);
