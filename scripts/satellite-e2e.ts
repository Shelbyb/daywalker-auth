/**
 * Satellite domains: add/verify (DNS TXT stub), origin allow-list integration, primary domain, the PKCE-style redirect
 * handshake (sync -> code -> exchange) with its refusals, and the Next.js authProxy satellite flow end to end.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { NextRequest } from "next/server";
import { sql } from "drizzle-orm";
import { seedInstance } from "./seed";
import { db, closeDb } from "../src/lib/db";
import { cache, closeCache } from "../src/lib/cache";
import { createEnvironmentInstance } from "../src/lib/auth/application";
import { createBackendClient, verifyToken } from "../packages/sdk/src/server";
import { authProxy } from "../packages/sdk/src/nextjs";
import { createVerifier } from "../packages/sdk/src/core/satellite";

const AUTH = "http://localhost:3000";
let failures = 0;
const check = (name: string, ok: boolean, detail?: unknown) => {
  console.log(`${ok ? "✓" : "✗"} ${name}${ok ? "" : ` — ${JSON.stringify(detail)?.slice(0, 400)}`}`);
  if (!ok) failures++;
};
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const rows = async (q: ReturnType<typeof sql>) => (await db().execute(q)) as unknown as Record<string, any>[];
const DNS_FILE = process.env.DNS_TXT_TEST_FILE ?? "/tmp/daywalker-dns-test.json";
const publishTxt = (name: string, value: string) => {
  let map: Record<string, string[]> = {};
  try { map = JSON.parse(readFileSync(DNS_FILE, "utf8")); } catch { /* none yet */ }
  map[name] = [...(map[name] ?? []), value];
  writeFileSync(DNS_FILE, JSON.stringify(map));
};

const stamp = Date.now();
const SAT = `https://sat-${stamp}.example.org`;
const SAT2 = `https://sat2-${stamp}.example.net`;
const PRIMARY = `https://main-${stamp}.example.com`;
const inst = await seedInstance("Satellite E2E", ["http://localhost:3001"]);
const { instanceId, publishableKey: pk, secretKey: sk } = inst;
const be = createBackendClient({ secretKey: sk, apiUrl: AUTH });
const cfg = { publishableKey: pk, frontendApi: AUTH };
const api = async (method: string, path: string, body?: unknown, key = sk) => {
  const r = await fetch(`${AUTH}/v1/${path}`, { method, headers: { authorization: `Bearer ${key}`, "content-type": "application/json" }, body: body === undefined ? undefined : JSON.stringify(body) });
  return { status: r.status, body: await r.json().catch(() => null) };
};
const corsFor = async (origin: string, key = pk) => (await fetch(`${AUTH}/v1/client/environment`, { headers: { "x-publishable-key": key, origin } })).headers.get("access-control-allow-origin");

// ---------- Domains ----------
check("unauthenticated add refused", (await fetch(`${AUTH}/v1/satellite_domains`, { method: "POST", body: "{}" })).status === 401);
for (const [what, domain] of [["http", "http://insecure.example.org"], ["path", "https://x.example.org/app"], ["ip address", "https://192.0.2.10"], ["bare label", "https://intranet"], ["credentials", "https://u:p@x.example.org"], ["the service itself", AUTH]] as const) {
  const r = await api("POST", "satellite_domains", { domain });
  check(`rejects ${what}`, r.status === 400, r.body);
}
const prodSibling = await createEnvironmentInstance(inst.accountId, { name: "Satellite E2E", environment: "production", applicationId: inst.applicationId });
check("localhost refused on a production instance", (await api("POST", "satellite_domains", { domain: "http://localhost:3002" }, prodSibling.secretKey)).body?.error?.code === "domain_not_allowed");
const local = await be.satelliteDomains.add("http://localhost:3002");
check("localhost is verified at once on a development instance", local.verified && !local.dns, local);
check("localhost satellite joins the allow-list", (await corsFor("http://localhost:3002")) === "http://localhost:3002");
await be.satelliteDomains.remove(local.id);

const sat = await be.satelliteDomains.add(SAT);
check("added unverified with the TXT record to publish", !sat.verified && sat.dns?.name === `_daywalker.sat-${stamp}.example.org` && sat.dns.value.startsWith("daywalker-verify="), sat);
check("duplicate refused", (await api("POST", "satellite_domains", { domain: SAT })).status === 409);
check("unverified satellite is not an allowed origin", (await corsFor(SAT)) === null);
check("verify fails until the record exists", (await api("POST", `satellite_domains/${sat.id}/verify`)).body?.error?.code === "verification_failed");
publishTxt(sat.dns!.name, sat.dns!.value);
const ver = await be.satelliteDomains.verify(sat.id);
check("verified once the TXT record is there", ver.verified && !ver.dns, ver);
check("verified satellite is an allowed origin (CORS)", (await corsFor(SAT)) === SAT);
check("stored allowed origins are untouched", (await rows(sql`select allowed_origins from instances where id = ${instanceId}`))[0].allowed_origins.length === 1);
const other = await seedInstance("Satellite E2E other");
const dupOther = await api("POST", "satellite_domains", { domain: SAT }, other.secretKey);
publishTxt(dupOther.body.dns.name, dupOther.body.dns.value);
check("a verified origin can't be claimed by another app", (await api("POST", `satellite_domains/${dupOther.body.id}/verify`, undefined, other.secretKey)).body?.error?.code === "domain_taken");
check("another app can't remove or verify mine", (await api("DELETE", `satellite_domains/${sat.id}`, undefined, other.secretKey)).status === 404);
check("a 2nd domain is added and listed", (await be.satelliteDomains.add(SAT2)).origin === SAT2 && (await be.satelliteDomains.list()).length === 2);

// Primary domain
check("primary domain starts empty", (await be.satelliteDomains.getPrimary()).primaryDomain === null);
check("primary can't be an existing satellite", (await api("PUT", "instance/primary_domain", { primaryDomain: SAT })).body?.error?.code === "domain_is_satellite");
check("primary domain saved", (await be.satelliteDomains.setPrimary(PRIMARY)).primaryDomain === PRIMARY);
check("primary domain is an allowed origin", (await corsFor(PRIMARY)) === PRIMARY);
check("a satellite can't be the primary", (await api("POST", "satellite_domains", { domain: PRIMARY })).body?.error?.code === "domain_is_primary");

// ---------- A signed-in person ----------
const password = "a long enough password";
const su = await fetch(`${AUTH}/v1/client/sign_up`, { method: "POST", headers: { "content-type": "application/json", "x-publishable-key": pk, origin: "http://localhost:3001", "x-forwarded-for": "203.0.113.70" }, body: JSON.stringify({ email: `sat.${stamp}@example.com`, password }) });
const cookie = (su.headers.get("set-cookie") ?? "").split(";")[0];
const sync = (o: { cookie?: string; ret?: string; challenge?: string | null; to?: string; primary?: string; key?: string } = {}) => {
  const u = new URL(`${AUTH}/v1/client/satellite/sync`);
  u.searchParams.set("pk", o.key ?? pk);
  u.searchParams.set("return", o.ret ?? SAT);
  if (o.challenge !== null) u.searchParams.set("challenge", o.challenge ?? "x".repeat(43));
  u.searchParams.set("to", o.to ?? `${SAT}/private`);
  if (o.primary) u.searchParams.set("primary", o.primary);
  return fetch(u, { redirect: "manual", headers: { ...(o.cookie ? { cookie: o.cookie } : {}), "x-forwarded-for": "203.0.113.71" } });
};
const exchange = (code: string, verifier: string, key = pk) => fetch(`${AUTH}/v1/client/satellite/exchange`, { method: "POST", headers: { "content-type": "application/json", "x-publishable-key": key }, body: JSON.stringify({ code, verifier }) }).then(async (r) => ({ status: r.status, body: await r.json().catch(() => null) }));

const v1 = await createVerifier();
const r1 = await sync({ cookie, challenge: v1.challenge });
const loc1 = new URL(r1.headers.get("location") ?? "http://none");
check("sync redirects to the satellite's fixed handshake path with a code", r1.status === 302 && loc1.origin === SAT && loc1.pathname === "/__daywalker/handshake" && !!loc1.searchParams.get("code") && loc1.searchParams.get("to") === `${SAT}/private`, r1.headers.get("location"));
check("redirect isn't cacheable", (r1.headers.get("cache-control") ?? "").includes("no-store"));
const code1 = loc1.searchParams.get("code")!;
const stored = (await cache().keys("sat:code:*"));
const raw = stored.length ? await cache().get(stored[0]) : "";
check("the token is stored encrypted, not as a JWT", !!raw && !/eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\./.test(raw!), raw?.slice(0, 80));
check("wrong verifier refused (and burns the code)", (await exchange(code1, "w".repeat(43))).body?.error?.code === "invalid_code" && (await exchange(code1, v1.verifier)).body?.error?.code === "invalid_code");
const r2 = await sync({ cookie, challenge: v1.challenge });
const code2 = new URL(r2.headers.get("location")!).searchParams.get("code")!;
check("another instance's key can't exchange it", (await exchange(code2, v1.verifier, other.publishableKey)).status === 400);
const r2b = await sync({ cookie, challenge: v1.challenge });
const code2b = new URL(r2b.headers.get("location")!).searchParams.get("code")!;
const ex = await exchange(code2b, v1.verifier);
const claims = await verifyToken(ex.body?.jwt, { ...cfg, authorizedParties: [SAT] });
check("exchange returns a token for the satellite (azp = its origin)", ex.status === 200 && claims?.azp === SAT && !!claims.userId, [ex.body, claims]);
check("the token is refused where other origins are required", (await verifyToken(ex.body.jwt, { ...cfg, authorizedParties: ["https://other.example.org"] })) === null);
check("a code works only once", (await exchange(code2b, v1.verifier)).body?.error?.code === "invalid_code");
// expiry
const r3 = await sync({ cookie, challenge: v1.challenge });
const code3 = new URL(r3.headers.get("location")!).searchParams.get("code")!;
for (const k of await cache().keys("sat:code:*")) await cache().pexpire(k, 1);
await new Promise((r) => setTimeout(r, 50));
check("an expired code is refused", (await exchange(code3, v1.verifier)).body?.error?.code === "invalid_code");
// satellite removed between redirect and exchange
const satTmp = await be.satelliteDomains.add(`https://tmp-${stamp}.example.org`);
publishTxt(satTmp.dns!.name, satTmp.dns!.value);
await be.satelliteDomains.verify(satTmp.id);
const r4 = await sync({ cookie, challenge: v1.challenge, ret: satTmp.origin, to: `${satTmp.origin}/` });
const code4 = new URL(r4.headers.get("location")!).searchParams.get("code")!;
await be.satelliteDomains.remove(satTmp.id);
check("removing the satellite invalidates codes in flight", (await exchange(code4, v1.verifier)).body?.error?.code === "invalid_code");

// refusals
const evil = await sync({ cookie, ret: "https://evil.example.com", challenge: v1.challenge });
check("an origin that isn't a verified satellite is not redirected to", evil.status === 403 && !evil.headers.get("location"), evil.status);
const unverified = await sync({ cookie, ret: SAT2, challenge: v1.challenge });
check("an unverified satellite is not redirected to", unverified.status === 403 && !unverified.headers.get("location"));
check("the primary domain can't receive sessions (satellites only)", (await sync({ cookie, ret: PRIMARY, challenge: v1.challenge })).status === 403);
check("missing/invalid challenge refused", (await sync({ cookie, challenge: null })).status === 400 && (await sync({ cookie, challenge: "short" })).status === 400);
check("primary mismatch refused", (await sync({ cookie, challenge: v1.challenge, primary: "https://not-main.example.com" })).status === 400);
check("matching primary accepted", (await sync({ cookie, challenge: v1.challenge, primary: PRIMARY })).status === 302);
const so = await sync({ challenge: v1.challenge });
check("no session: sent back signed_out, no code", so.status === 302 && new URL(so.headers.get("location")!).searchParams.get("status") === "signed_out" && !new URL(so.headers.get("location")!).searchParams.get("code"));
const sid = (await rows(sql`select id from sessions where instance_id = ${instanceId} order by created_at desc limit 1`))[0].id;
await rows(sql`update sessions set dpop_jkt = 'bound-key' where id = ${sid}`);
for (const k of await cache().keys("sess:*")) await cache().del(k);
const bound = await sync({ cookie, challenge: v1.challenge });
check("a device-bound session is not shared (looks signed out)", new URL(bound.headers.get("location")!).searchParams.get("status") === "signed_out");
await rows(sql`update sessions set dpop_jkt = null where id = ${sid}`);
for (const k of await cache().keys("sess:*")) await cache().del(k);
check("exchange rejects junk", (await exchange("x", "y")).status === 400);

// Hosted sign-in accepts a satellite as redirect target
const page = await (await fetch(`${AUTH}/sign-in?pk=${encodeURIComponent(pk)}&redirect_url=${encodeURIComponent(`${SAT}/__daywalker/sync?to=%2Fprivate`)}`)).text();
check("hosted sign-in keeps a satellite redirect_url", page.includes(`sat-${stamp}.example.org`));

// ---------- authProxy on the satellite ----------
const scfg = { ...cfg, isSatellite: true, primaryDomain: PRIMARY, domain: SAT, authorizedParties: [SAT] };
const proxy = authProxy({ protect: ["/private*", "/api/private*"], syncPaths: ["/"], config: scfg });
const req = (path: string, cookies: Record<string, string> = {}, headers: Record<string, string> = {}) =>
  new NextRequest(`${SAT}${path}`, { headers: { accept: "text/html", ...(Object.keys(cookies).length ? { cookie: Object.entries(cookies).map(([k, v]) => `${k}=${v}`).join("; ") } : {}), ...headers } });
const setCookies = (res: Response) => Object.fromEntries(res.headers.getSetCookie().map((c) => [c.split("=")[0], c.split(";")[0].slice(c.indexOf("=") + 1)]));
const rawSetCookie = (res: Response, name: string) => res.headers.getSetCookie().find((c) => c.startsWith(`${name}=`)) ?? "";

check("public pages pass through", (await proxy(req("/about"))).headers.get("x-middleware-next") === "1");
const p1 = await proxy(req("/private/area?x=1"));
check("protected page without a token starts a silent sync", p1.status === 302 && new URL(p1.headers.get("location")!).pathname === "/__daywalker/sync" && new URL(p1.headers.get("location")!).searchParams.get("to") === "/private/area?x=1", p1.headers.get("location"));
check("API requests get 401, not a redirect", (await proxy(req("/api/private/x", {}, { accept: "application/json" }))).status === 401);
const pre = await proxy(req("/private", {}, { "next-router-prefetch": "1" }));
check("prefetches don't trigger a sync", pre.status >= 300 && pre.status < 400 && !new URL(pre.headers.get("location")!).pathname.startsWith("/__daywalker"), pre.headers.get("location"));

const s1 = await proxy(req(`/__daywalker/sync?to=${encodeURIComponent("https://evil.example.com/steal")}`));
const s1loc = new URL(s1.headers.get("location")!);
check("sync goes to the service with pk, return, challenge and primary", s1.status === 302 && s1loc.origin === AUTH && s1loc.pathname === "/v1/client/satellite/sync" && s1loc.searchParams.get("return") === SAT && s1loc.searchParams.get("primary") === PRIMARY && s1loc.searchParams.get("challenge")?.length === 43, s1.headers.get("location"));
check("a foreign `to` is replaced by /", s1loc.searchParams.get("to") === `${SAT}/`);
check("the verifier cookie is httpOnly and scoped to the handshake path", /HttpOnly/i.test(rawSetCookie(s1, "__dw_sat_v")) && /Path=\/__daywalker\/handshake/.test(rawSetCookie(s1, "__dw_sat_v")));

// signed-in flow
const s2 = await proxy(req("/__daywalker/sync?to=%2Fprivate%2Farea"));
const verifierCookie = setCookies(s2).__dw_sat_v;
const toService = await fetch(s2.headers.get("location")!, { redirect: "manual", headers: { cookie, "x-forwarded-for": "203.0.113.72" } });
const back = new URL(toService.headers.get("location")!);
check("the service sends the browser back with a code", toService.status === 302 && back.origin === SAT && !!back.searchParams.get("code"), toService.headers.get("location"));
const hs = await proxy(req(`${back.pathname}${back.search}`, { __dw_sat_v: verifierCookie }));
const hc = setCookies(hs);
check("handshake sets the session cookie and returns to the page", hs.status === 302 && new URL(hs.headers.get("location")!).pathname === "/private/area" && !!hc.__dw_session && hc.__dw_active === "1", [hs.status, hs.headers.get("location"), Object.keys(hc)]);
check("the verifier cookie is cleared", /Max-Age=0/i.test(rawSetCookie(hs, "__dw_sat_v")));
const synced = await verifyToken(hc.__dw_session, scfg);
check("the synced token verifies like any session token", !!synced && synced.azp === SAT, synced);
check("with the synced cookie the protected page loads", (await proxy(req("/private/area", { __dw_session: hc.__dw_session }))).headers.get("x-middleware-next") === "1");
check("the handshake link can't be replayed without the verifier cookie", (await proxy(req(`${back.pathname}${back.search}`))).headers.getSetCookie().some((c) => c.startsWith("__dw_sat_out=1")));

// signed-out flow
const s3 = await proxy(req("/__daywalker/sync?to=%2Fprivate"));
const toService3 = await fetch(s3.headers.get("location")!, { redirect: "manual", headers: { "x-forwarded-for": "203.0.113.73" } });
const back3 = new URL(toService3.headers.get("location")!);
const hs3 = await proxy(req(`${back3.pathname}${back3.search}`, { __dw_sat_v: setCookies(s3).__dw_sat_v }));
check("signed out: flag cookie set, no loop", hs3.status === 302 && setCookies(hs3).__dw_sat_out === "1");
const p3 = await proxy(req("/private", { __dw_sat_out: "1" }));
const p3loc = new URL(p3.headers.get("location")!);
check("then protected pages go to sign-in, returning through the sync", p3loc.origin === AUTH && p3loc.pathname === "/sign-in" && p3loc.searchParams.get("redirect_url") === `${SAT}/__daywalker/sync?to=${encodeURIComponent("/private")}`, p3.headers.get("location"));
check("public sync page doesn't redirect after a signed-out result", (await proxy(req("/", { __dw_sat_out: "1" }))).headers.get("x-middleware-next") === "1");
check("public sync page syncs quietly otherwise", (await proxy(req("/"))).status === 302);
const loop = await proxy(req("/__daywalker/sync?to=%2F", { __dw_sat_try: "4" }));
check("a redirect loop ends in an error page", loop.status === 508);
check("handshake with a bad code leaves the person signed out", setCookies(await proxy(req("/__daywalker/handshake?code=nope&to=%2F", { __dw_sat_v: v1.verifier }))).__dw_sat_out === "1");

// Config validation
let threw = false;
try { await authProxy({ protect: ["/x*"], config: { ...cfg, isSatellite: true } })(req("/x")); } catch { threw = true; }
check("isSatellite without primaryDomain fails loudly", threw);
check("a non-satellite proxy ignores the handshake paths", (await authProxy({ protect: ["/x*"], config: cfg })(req("/__daywalker/sync"))).headers.get("x-middleware-next") === "1");

const audit = await api("GET", "audit_events?limit=100");
const types = new Set(audit.body.data.map((e: { type: string }) => e.type));
check("audit records domain changes", ["satellite_domain.added", "satellite_domain.verified", "satellite_domain.removed", "instance.primary_domain_updated"].every((t) => types.has(t)), [...types]);

console.log(failures ? `\n${failures} check(s) failed` : "\nAll satellite checks passed");
await closeDb();
await closeCache();
process.exit(failures ? 1 : 0);
