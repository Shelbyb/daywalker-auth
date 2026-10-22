/** Breached-password check against a local mock of the Pwned Passwords range API (port 3997). */
import { createServer } from "node:http";
import { createHash } from "node:crypto";
import { sql } from "drizzle-orm";
import { seedInstance } from "./seed";
import { cache, closeCache } from "../src/lib/cache";
import { blindIndex } from "../src/lib/crypto";
import { db, closeDb } from "../src/lib/db";
import { invalidateInstance } from "../src/lib/auth/instance";

const BASE = "http://localhost:3000";
let failures = 0;
const check = (name: string, ok: boolean, detail?: unknown) => {
  console.log(`${ok ? "✓" : "✗"} ${name}${ok ? "" : ` — ${JSON.stringify(detail)?.slice(0, 300)}`}`);
  if (!ok) failures++;
};
const sha1 = (s: string) => createHash("sha1").update(s).digest("hex").toUpperCase();

const BREACHED = "this password was leaked 2019";
const PADDED_ONLY = "this one only appears as padding";
const SAFE = "a perfectly fine fresh passphrase";

// ---------- Mock API ----------
let mode: "ok" | "down" | "slow" = "ok";
const seen: { url: string; padding: string | undefined }[] = [];
const server = createServer((req, res) => {
  seen.push({ url: req.url ?? "", padding: req.headers["add-padding"] as string | undefined });
  if (mode === "down") return res.writeHead(503).end();
  const prefix = (req.url ?? "").split("/range/")[1] ?? "";
  const rows: string[] = [];
  for (let i = 0; i < 400; i++) rows.push(`${createHash("sha1").update(`${prefix}${i}`).digest("hex").toUpperCase().slice(5)}:${i % 7}`);
  if (sha1(BREACHED).startsWith(prefix)) rows.push(`${sha1(BREACHED).slice(5)}:4213`);
  if (sha1(PADDED_ONLY).startsWith(prefix)) rows.push(`${sha1(PADDED_ONLY).slice(5)}:0`);
  const send = () => res.writeHead(200, { "content-type": "text/plain" }).end(rows.join("\r\n"));
  if (mode === "slow") setTimeout(send, 5000);
  else send();
});
await new Promise<void>((r) => server.listen(3997, r));

const seed = await seedInstance("Breach E2E", []);
const pk = seed.publishableKey;
function jar() {
  let cookie = "";
  return async (path: string, body?: unknown) => {
    const res = await fetch(`${BASE}/v1/client/${path}`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-publishable-key": pk, origin: BASE, "x-forwarded-for": `192.0.2.${Math.floor(Math.random() * 250) + 1}`, ...(cookie ? { cookie } : {}) },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    for (const c of res.headers.getSetCookie()) if (c.startsWith("__dw_rt")) cookie = c.split(";")[0];
    return { status: res.status, body: await res.json().catch(() => null) };
  };
}
const userCount = async (email: string) =>
  Number(((await db().execute(sql`select count(*)::int as n from email_addresses where instance_id = ${seed.instanceId} and email_index = ${blindIndex(email, `email:${seed.instanceId}`)}`)) as unknown as { n: number }[])[0].n);
const em = (tag: string) => `${tag}.${Date.now()}.${Math.random().toString(36).slice(2, 6)}@example.com`;

// ---------- Sign-up ----------
const e1 = em("breached");
const r1 = await jar()("sign_up", { email: e1, password: BREACHED });
check("sign-up with a breached password → 400 password_breached", r1.status === 400 && r1.body.error.code === "password_breached", r1.body);
check("…with a clear message", /data breach/.test(r1.body.error.message));
check("…and no account is created", (await userCount(e1)) === 0);
const e2 = em("safe");
const r2 = await jar()("sign_up", { email: e2, password: SAFE });
check("sign-up with a fresh password works", r2.status === 201 && !!r2.body.user);
check("a hash that only appears as padding (count 0) is not treated as breached", (await jar()("sign_up", { email: em("pad"), password: PADDED_ONLY })).status === 201);

// ---------- What was sent ----------
const urls = seen.map((s) => s.url);
check("only a 5-character hash prefix is sent", urls.length > 0 && urls.every((u) => /^\/range\/[0-9A-F]{5}$/.test(u)), urls);
check("the full hash and the password are never sent", !urls.some((u) => u.includes(sha1(BREACHED).slice(5)) || u.includes(encodeURIComponent(BREACHED))));
check("responses are requested with padding", seen.every((s) => s.padding === "true"));

// ---------- Change and reset ----------
const a = jar();
const e3 = em("change");
await a("sign_up", { email: e3, password: SAFE });
await a("sign_in", { email: e3, password: SAFE });
const chg = await a("password/change", { currentPassword: SAFE, newPassword: BREACHED });
const chgBody = chg.body;
check("changing to a breached password → 400 password_breached", chg.status === 400 && chgBody.error?.code === "password_breached", chgBody);

await jar()("password/forgot", { email: e3 });
const code = (await cache().get(`devmail:${blindIndex(e3, "devmail")}`))?.match(/\b(\d{6})\b/)?.[1];
const rs1 = await jar()("password/reset", { email: e3, code, password: BREACHED });
check("resetting to a breached password → 400 password_breached", rs1.status === 400 && rs1.body.error.code === "password_breached", rs1.body);
const rs2 = await jar()("password/reset", { email: e3, code, password: "another fresh passphrase here" });
check("…and the reset code still works for a better password", rs2.status === 200, rs2.body);

// ---------- Turned off ----------
await db().execute(sql`update instances set settings = settings || '{"breachedPasswordCheck":false}'::jsonb where id = ${seed.instanceId}`);
await invalidateInstance(seed.instanceId);
check("with the check turned off, a breached password is accepted", (await jar()("sign_up", { email: em("off"), password: BREACHED })).status === 201);
await db().execute(sql`update instances set settings = settings - 'breachedPasswordCheck' where id = ${seed.instanceId}`);
await invalidateInstance(seed.instanceId);
check("on by default (setting absent → checked)", (await jar()("sign_up", { email: em("default"), password: BREACHED })).status === 400);

// ---------- Fails open ----------
mode = "down";
check("API down → sign-up still works (fails open)", (await jar()("sign_up", { email: em("down"), password: BREACHED })).status === 201);
mode = "slow";
const t0 = Date.now();
const slow = await jar()("sign_up", { email: em("slow"), password: BREACHED });
const took = Date.now() - t0;
check("API slow → gives up after the timeout and lets sign-up through", slow.status === 201 && took < 4500, { status: slow.status, took });

server.close();
await closeDb();
await closeCache();
console.log(failures ? `\n${failures} check(s) failed` : "\nAll breached-password checks passed");
process.exit(failures ? 1 : 0);
