/**
 * Device-bound sessions (DPoP, RFC 9449): proof validation, binding at sign-in and via /session/bind,
 * stolen-cookie rejection, off/optional/required modes, replay, and the SDK client against the live server.
 */
import { createSign, generateKeyPairSync, randomBytes, type KeyObject } from "node:crypto";
import { sql } from "drizzle-orm";
import { seedInstance } from "./seed";
import { db, closeDb } from "../src/lib/db";
import { cache, closeCache } from "../src/lib/cache";
import { sha256 } from "../src/lib/ids";
import { createAuthClient } from "../packages/sdk/src/core";
import { createDpopProof, generateDeviceKey, INLINE_PROOF_SOURCE, type DeviceKey, type DeviceKeyStore } from "../packages/sdk/src/core/dpop";
import { verifyToken } from "../packages/sdk/src/server";
import { jwtVerify, createLocalJWKSet } from "jose";

const AUTH = "http://localhost:3000";
let failures = 0;
const check = (name: string, ok: boolean, detail?: unknown) => {
  console.log(`${ok ? "✓" : "✗"} ${name}${ok ? "" : ` — ${JSON.stringify(detail)?.slice(0, 400)}`}`);
  if (!ok) failures++;
};
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const rows = async (q: ReturnType<typeof sql>) => (await db().execute(q)) as unknown as Record<string, any>[];

const { instanceId, publishableKey: pk, secretKey: sk } = await seedInstance("Binding E2E", ["http://localhost:3001"]);
let n = 0;
const b64u = (v: unknown) => Buffer.from(typeof v === "string" ? v : JSON.stringify(v)).toString("base64url");

/** Hand-made proof so we can break individual rules. */
function forge(opts: { method?: string; path: string; header?: Record<string, unknown>; payload?: Record<string, unknown>; kp?: { publicKey: KeyObject; privateKey: KeyObject } }) {
  const kp = opts.kp ?? generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = kp.publicKey.export({ format: "jwk" });
  const h = b64u({ typ: "dpop+jwt", alg: "ES256", jwk: { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y }, ...opts.header });
  const p = b64u({ jti: randomBytes(12).toString("base64url"), htm: opts.method ?? "POST", htu: `${AUTH}${opts.path}`, iat: Math.floor(Date.now() / 1000), ...opts.payload });
  const s = createSign("SHA256").update(`${h}.${p}`).sign({ key: kp.privateKey, dsaEncoding: "ieee-p1363" });
  return `${h}.${p}.${s.toString("base64url")}`;
}

const raw = async (path: string, o: { method?: string; body?: unknown; cookie?: string; proof?: string | null; headers?: Record<string, string> } = {}) => {
  const method = o.method ?? "POST";
  const r = await fetch(`${AUTH}/v1/client/${path}`, {
    method,
    headers: { "content-type": "application/json", "x-publishable-key": pk, origin: AUTH, "x-forwarded-for": `203.0.113.${(++n % 200) + 1}`, ...(o.cookie ? { cookie: o.cookie } : {}), ...(o.proof ? { dpop: o.proof } : {}), ...o.headers },
    body: method === "GET" ? undefined : JSON.stringify(o.body ?? {}),
  });
  return { status: r.status, body: await r.json().catch(() => null), cookie: (r.headers.get("set-cookie") ?? "").split(";")[0], headers: r.headers };
};
/** Request with a valid proof from `key`. */
const withKey = async (key: DeviceKey | null, path: string, o: { method?: string; body?: unknown; cookie?: string } = {}) =>
  raw(path, { ...o, proof: key ? await createDpopProof(key, o.method ?? "POST", `${AUTH}/v1/client/${path}`) : null });
const mode = async (m: string) => fetch(`${AUTH}/v1/instance/device_binding`, { method: "PATCH", headers: { authorization: `Bearer ${sk}`, "content-type": "application/json" }, body: JSON.stringify({ mode: m }) });
const resetLimit = async () => { const k = await cache().keys(`rl:${instanceId}:*`); if (k.length) await cache().del(...k); };
const password = "a long enough password";
const stamp = Date.now();
const signUp = async (tag: string) => {
  const email = `${tag}.${stamp}@example.com`;
  const su = await raw("sign_up", { body: { email, password } });
  return { email, id: su.body.user.id as string };
};
const code = (r: { body: { error?: { code?: string } } | null }) => r.body?.error?.code;

// ---------- Settings API ----------
const get0 = await (await fetch(`${AUTH}/v1/instance/device_binding`, { headers: { authorization: `Bearer ${sk}` } })).json();
check("default mode is off", get0.mode === "off", get0);
check("invalid mode rejected (422)", (await mode("sometimes")).status === 422);
check("unauthenticated settings call rejected", (await fetch(`${AUTH}/v1/instance/device_binding`, { method: "PATCH", body: "{}" })).status === 401);

// ---------- Off: a proof is ignored, nothing is bound ----------
const keyA = await generateDeviceKey();
const u1 = await signUp("off");
const off = await withKey(keyA, "sign_in", { body: { email: u1.email, password } });
check("off: sign-in with a proof still works", off.status === 200 && !!off.cookie);
const offRow = await rows(sql`select dpop_jkt from sessions where instance_id = ${instanceId} and user_id = ${u1.id} order by created_at desc limit 1`);
check("off: session not bound", offRow[0].dpop_jkt === null, offRow);
check("off: token works without proof", (await raw("session/token", { cookie: off.cookie })).status === 200);
check("environment reports the mode", (await raw("environment", { method: "GET" })).body.sessions.deviceBinding === "off");
check("off: bind refused", code(await withKey(keyA, "session/bind", { cookie: off.cookie })) === "device_binding_off");

// ---------- Optional ----------
check("set optional", (await mode("optional")).status === 200);
await new Promise((r) => setTimeout(r, 100));
check("environment reports optional", (await raw("environment", { method: "GET" })).body.sessions.deviceBinding === "optional");
const bound = await withKey(keyA, "sign_in", { body: { email: u1.email, password } });
check("optional: sign-in with a proof binds the session", bound.status === 200, bound.body);
const jkt = (await rows(sql`select dpop_jkt from sessions where instance_id = ${instanceId} and user_id = ${u1.id} order by created_at desc limit 1`))[0].dpop_jkt as string;
check("session stores a thumbprint", typeof jkt === "string" && jkt.length === 43, jkt);
const tok = await withKey(keyA, "session/token", { cookie: bound.cookie });
check("bound: token with the right proof works", tok.status === 200 && !!tok.body.jwt, tok);
// JWT carries cnf.jkt and verifies with the SDK
const jwks = createLocalJWKSet(await (await fetch(`${AUTH}/i/${instanceId}/.well-known/jwks.json`)).json());
const { payload } = await jwtVerify(tok.body.jwt, jwks);
check("JWT has cnf.jkt equal to the session thumbprint", (payload.cnf as { jkt?: string })?.jkt === jkt, payload.cnf);
const claims = await verifyToken(tok.body.jwt, { publishableKey: pk, frontendApi: AUTH });
check("SDK verifyToken exposes deviceKey and keeps cnf out of custom claims", claims?.deviceKey === jkt && !("cnf" in (claims?.claims ?? {})), claims);

// Stolen cookie, no key
const stolen = await raw("session/token", { cookie: bound.cookie });
check("stolen cookie without a proof: 401 device_proof_required", stolen.status === 401 && code(stolen) === "device_proof_required", stolen);
check("stolen cookie: session read refused", (await raw("session", { method: "GET", cookie: bound.cookie })).status === 401);
check("stolen cookie: account actions refused", (await raw("mfa/totp", { cookie: bound.cookie })).status === 401);
check("stolen cookie: sessions list refused", (await raw("sessions", { method: "GET", cookie: bound.cookie })).status === 401);
const attacker = await generateDeviceKey();
const wrongKey = await withKey(attacker, "session/token", { cookie: bound.cookie });
check("another key's valid proof: 401 invalid_dpop_proof", wrongKey.status === 401 && code(wrongKey) === "invalid_dpop_proof", wrongKey);
check("still works for the real device afterwards", (await withKey(keyA, "session/token", { cookie: bound.cookie })).status === 200);
check("session read with the key works", (await withKey(keyA, "session", { method: "GET", cookie: bound.cookie })).body.session?.deviceBound === true);

// Proof validation rules
const tokPath = "/v1/client/session/token";
const kp = generateKeyPairSync("ec", { namedCurve: "P-256" });
const at = async (proof: string, cookie = bound.cookie) => raw("session/token", { cookie, proof });
check("forged proof from an unknown key rejected", (await at(forge({ path: tokPath }))).status === 401);
check("wrong method (htm) rejected", code(await at(forge({ path: tokPath, payload: { htm: "GET" } }))) === "invalid_dpop_proof");
check("wrong URL (htu) rejected", code(await at(forge({ path: "/v1/client/session" }))) === "invalid_dpop_proof");
check("wrong origin in htu rejected", code(await at(forge({ path: tokPath, payload: { htu: "https://evil.example/v1/client/session/token" } }))) === "invalid_dpop_proof");
check("stale proof (iat 5 min ago) rejected", code(await at(forge({ path: tokPath, payload: { iat: Math.floor(Date.now() / 1000) - 300 } }))) === "invalid_dpop_proof");
check("future proof (iat +5 min) rejected", code(await at(forge({ path: tokPath, payload: { iat: Math.floor(Date.now() / 1000) + 300 } }))) === "invalid_dpop_proof");
check("missing jti rejected", code(await at(forge({ path: tokPath, payload: { jti: undefined } }))) === "invalid_dpop_proof");
check("wrong typ rejected", code(await at(forge({ path: tokPath, header: { typ: "JWT" } }))) === "invalid_dpop_proof");
check("alg none rejected", code(await at(`${b64u({ typ: "dpop+jwt", alg: "none" })}.${b64u({ jti: "abcdefgh12", htm: "POST", htu: AUTH + tokPath, iat: Math.floor(Date.now() / 1000) })}.AAAA`)) === "invalid_dpop_proof");
check("HS256 rejected", code(await at(forge({ path: tokPath, header: { alg: "HS256" } }))) === "invalid_dpop_proof");
const privJwk = kp.publicKey.export({ format: "jwk" });
const withD = forge({ path: tokPath, kp, header: { jwk: { kty: "EC", crv: "P-256", x: privJwk.x, y: privJwk.y, d: "AAAA" } } });
check("jwk containing a private part rejected", code(await at(withD)) === "invalid_dpop_proof");
check("non-EC jwk rejected", code(await at(forge({ path: tokPath, header: { jwk: { kty: "RSA", n: "AQAB", e: "AQAB" } } }))) === "invalid_dpop_proof");
check("tampered signature rejected", code(await at(await (async () => { const [h, p, sig] = (await createDpopProof(keyA, "POST", AUTH + tokPath)).split("."); return `${h}.${p}.${sig.slice(0, 10)}${sig[10] === "A" ? "B" : "A"}${sig.slice(11)}`; })())) === "invalid_dpop_proof");
check("garbage proof header rejected", code(await at("not-a-jwt")) === "invalid_dpop_proof");
check("oversized proof rejected", code(await at(`${"a".repeat(5000)}.b.c`)) === "invalid_dpop_proof");
const dup = await createDpopProof(keyA, "POST", AUTH + tokPath);
check("proof accepted once", (await at(dup)).status === 200);
const replay = await at(dup);
check("replayed proof rejected", replay.status === 401 && code(replay) === "invalid_dpop_proof", replay);
const twice = await at(`${dup}, ${await createDpopProof(keyA, "POST", AUTH + tokPath)}`);
check("two proofs in one header rejected", code(twice) === "invalid_dpop_proof", twice);
check("query string is not part of htu", (await raw("session/token?x=1", { cookie: bound.cookie, proof: await createDpopProof(keyA, "POST", AUTH + tokPath) })).status === 200);

// Sign-out needs only the cookie (the key may be lost)
const out = await raw("session", { method: "DELETE", cookie: bound.cookie });
check("sign-out with the cookie alone works", out.status === 200);
check("then the session is gone", (await withKey(keyA, "session/token", { cookie: bound.cookie })).status === 401);

// Optional: unbound sign-in still works; no proof, no binding
const plain = await raw("sign_in", { body: { email: u1.email, password } });
check("optional: sign-in without a proof works (unbound)", plain.status === 200);
check("optional: unbound token works without a proof", (await raw("session/token", { cookie: plain.cookie })).status === 200);
check("sign-in with a bad proof is refused, not downgraded", (await raw("sign_in", { body: { email: u1.email, password }, proof: forge({ path: "/v1/client/sign_in", payload: { htm: "GET" } }) })).status === 401);

// ---------- Bind endpoint (redirect-style sign-ins) ----------
const keyB = await generateDeviceKey();
check("bind without a proof refused", code(await raw("session/bind", { cookie: plain.cookie })) === "device_proof_required");
check("bind without a session refused", (await withKey(keyB, "session/bind")).status === 401);
const sess0 = await raw("session", { method: "GET", cookie: plain.cookie });
check("session says it can still be bound", sess0.body.session.deviceBound === false && sess0.body.session.deviceBindable === true && sess0.body.session.deviceBinding === "optional", sess0.body);
const b1 = await withKey(keyB, "session/bind", { cookie: plain.cookie });
check("bind within the window works", b1.status === 200 && b1.body.deviceBound === true, b1);
check("after binding, no proof is refused", (await raw("session/token", { cookie: plain.cookie })).status === 401);
check("after binding, the new key works", (await withKey(keyB, "session/token", { cookie: plain.cookie })).status === 200);
const b2 = await withKey(attacker, "session/bind", { cookie: plain.cookie });
check("a bound session can't be re-bound (409)", b2.status === 409 && code(b2) === "already_bound", b2);
check("and the original key still works", (await withKey(keyB, "session/token", { cookie: plain.cookie })).status === 200);

// Window closed
const old = await raw("sign_in", { body: { email: u1.email, password } });
const oldHash = sha256(old.cookie.split("=")[1]);
await db().execute(sql`update sessions set created_at = now() - interval '10 minutes' where refresh_token_hash = ${oldHash}`);
await cache().del(`sess:${oldHash}`);
const late = await withKey(keyB, "session/bind", { cookie: old.cookie });
check("bind after the window refused (403 bind_window_closed)", late.status === 403 && code(late) === "bind_window_closed", late);
check("optional: that unbound old session keeps working", (await raw("session/token", { cookie: old.cookie })).status === 200);
check("an old session reports it can't be bound", (await raw("session", { method: "GET", cookie: old.cookie })).body.session.deviceBindable === false);

// ---------- Required ----------
check("set required", (await mode("required")).status === 200);
await new Promise((r) => setTimeout(r, 100));
await resetLimit();
const noKey = await raw("sign_in", { body: { email: u1.email, password } });
check("required: sign-in without a proof refused (400 device_key_required)", noKey.status === 400 && code(noKey) === "device_key_required" && !noKey.cookie, noKey);
const sessCount = await rows(sql`select count(*)::int c from sessions where user_id = ${u1.id}`);
const noKey2 = await raw("sign_in", { body: { email: u1.email, password } });
check("required: refusal creates no session", (await rows(sql`select count(*)::int c from sessions where user_id = ${u1.id}`))[0].c === sessCount[0].c && noKey2.status === 400);
check("required: sign-up without a proof refused", code(await raw("sign_up", { body: { email: `nokey.${stamp}@example.com`, password } })) === "device_key_required");
const req1 = await withKey(keyA, "sign_in", { body: { email: u1.email, password } });
check("required: sign-in with a proof works", req1.status === 200 && !!req1.body.jwt, req1.body);
check("required: token needs the proof", (await raw("session/token", { cookie: req1.cookie })).status === 401);
check("required: token with proof works", (await withKey(keyA, "session/token", { cookie: req1.cookie })).status === 200);
check("required: old unbound session (past the window) is cut off", code(await raw("session/token", { cookie: old.cookie })) === "device_binding_required");
check("required: and cannot be bound late", (await withKey(keyB, "session/bind", { cookie: old.cookie })).status === 403);
check("required: bound session from before still works with its key", (await withKey(keyB, "session/token", { cookie: plain.cookie })).status === 200);

// A young unbound session (what a redirect sign-in leaves behind) can only be bound
await mode("optional");
await new Promise((r) => setTimeout(r, 100));
await resetLimit();
const young = await raw("sign_in", { body: { email: u1.email, password } });
await mode("required");
await new Promise((r) => setTimeout(r, 100));
check("required: young unbound session may not mint tokens", code(await raw("session/token", { cookie: young.cookie })) === "device_binding_required");
check("required: nor read account data", (await raw("sessions", { method: "GET", cookie: young.cookie })).status === 401);
check("required: but may look at itself", (await raw("session", { method: "GET", cookie: young.cookie })).body.session?.deviceBindable === true);
check("required: and be bound", (await withKey(keyA, "session/bind", { cookie: young.cookie })).status === 200);
check("required: then works with the key", (await withKey(keyA, "session/token", { cookie: young.cookie })).status === 200);

// Required: second-factor step and passkey-free JSON paths carry the proof too (email code)
await mode("optional");
await new Promise((r) => setTimeout(r, 100));
await resetLimit();

// Audit + dashboard setting
const aud = await rows(sql`select type from audit_events where instance_id = ${instanceId} and type in ('session.device_bound','instance.sessions_updated')`);
check("binding is audited", aud.some((a) => a.type === "session.device_bound") && aud.some((a) => a.type === "instance.sessions_updated"), aud);
const preflight = await fetch(`${AUTH}/v1/client/session/token`, { method: "OPTIONS", headers: { origin: AUTH, "x-publishable-key": pk, "access-control-request-method": "POST" } });
check("CORS preflight allows the DPoP header", (preflight.headers.get("access-control-allow-headers") ?? "").includes("dpop"), preflight.headers.get("access-control-allow-headers"));

// ---------- Impersonation-style session without a key is exempt (platform) -> covered by platform-e2e ----------

// ---------- SDK client end to end (memory key store + cookie jar) ----------
const origFetch = globalThis.fetch;
let jar = "";
globalThis.fetch = (async (input: RequestInfo | URL, init: RequestInit = {}) => {
  const h = new Headers(init.headers);
  h.set("origin", AUTH);
  h.set("x-forwarded-for", `198.51.100.${(++n % 200) + 1}`);
  if (jar) h.set("cookie", jar);
  const r = await origFetch(input, { ...init, headers: h });
  const sc = r.headers.get("set-cookie");
  if (sc) jar = sc.split(";")[0].endsWith("=") ? "" : sc.split(";")[0];
  return r;
}) as typeof fetch;
const mem = new Map<string, DeviceKey>();
const store: DeviceKeyStore = { get: async (i) => mem.get(i), put: async (i, k) => void mem.set(i, k), delete: async (i) => void mem.delete(i) };
const u2 = await signUp("sdk");
await mode("required");
await new Promise((r) => setTimeout(r, 100));
await resetLimit();
const client = createAuthClient({ publishableKey: pk, frontendApi: AUTH, syncCookie: false, deviceKeyStore: store });
const si = await client.signIn({ email: u2.email, password });
check("SDK: signs in under required binding (key created on demand)", si.status === "complete" && mem.size === 1, si);
const t1 = await client.getToken({ force: true });
check("SDK: refresh attaches proofs", !!t1);
const stolenJar = jar;
check("SDK: the cookie alone (without the key) does not refresh", (await raw("session/token", { cookie: stolenJar })).status === 401);
const fresh = createAuthClient({ publishableKey: pk, frontendApi: AUTH, syncCookie: false, deviceKeyStore: store });
check("SDK: a new client with the same key store resumes the session", (await fresh.load()).user?.id === u2.id);
const noStore = createAuthClient({ publishableKey: pk, frontendApi: AUTH, syncCookie: false, deviceKeyStore: { get: async () => undefined, put: async () => undefined, delete: async () => undefined } });
check("SDK: a browser that lost the key is signed out, not stuck", (await noStore.load()).user === null);
// redirect-style session: sign in without the SDK (optional mode), then the SDK binds it on load()
await mode("optional");
await new Promise((r) => setTimeout(r, 100));
await resetLimit();
const redirectLike = await origFetch(`${AUTH}/v1/client/sign_in`, { method: "POST", headers: { "content-type": "application/json", "x-publishable-key": pk, origin: AUTH, "x-forwarded-for": "203.0.113.250" }, body: JSON.stringify({ email: u2.email, password }) });
jar = (redirectLike.headers.get("set-cookie") ?? "").split(";")[0];
mem.clear();
const c2 = createAuthClient({ publishableKey: pk, frontendApi: AUTH, syncCookie: false, deviceKeyStore: store });
check("SDK: load() on a young unbound session (redirect sign-in) works", (await c2.load()).user?.id === u2.id);
const boundRows = await rows(sql`select dpop_jkt from sessions where refresh_token_hash = ${sha256(jar.split("=")[1])}`);
check("SDK: load() made a key and bound the redirect-style session", mem.size === 1 && typeof boundRows[0].dpop_jkt === "string", { size: mem.size, boundRows });
check("SDK: the cookie alone no longer works for that session", (await raw("session/token", { cookie: jar })).status === 401);
globalThis.fetch = origFetch;

// Inline proof snippet used by authProxy's refresh page matches the server's rules
const fakeKeys = new Map<string, DeviceKey>([[instanceId, keyA]]);
const fakeIdb = {
  open() {
    const req: { result?: unknown; onsuccess?: () => void; onupgradeneeded?: () => void; onerror?: () => void } = {};
    queueMicrotask(() => {
      req.result = {
        transaction: () => ({ objectStore: () => ({ get: (id: string) => { const q: { result?: unknown; onsuccess?: () => void } = {}; queueMicrotask(() => { q.result = fakeKeys.get(id); q.onsuccess?.(); }); return q; } }) }),
        close() {},
      };
      req.onsuccess?.();
    });
    return req;
  },
};
const dwProof = new Function("indexedDB", `${INLINE_PROOF_SOURCE}; return dwProof;`)(fakeIdb) as (i: string, m: string, u: string) => Promise<string | null>;
const inline = await dwProof(instanceId, "POST", `${AUTH}/v1/client/session/token`);
await mode("optional");
const bound2 = await withKey(keyA, "sign_in", { body: { email: u2.email, password } });
check("inline refresh-page proof is accepted by the server", !!inline && (await raw("session/token", { cookie: bound2.cookie, proof: inline })).status === 200);
check("inline snippet returns null when the browser has no key", (await dwProof("ins_missing", "POST", AUTH)) === null);

console.log(failures ? `\n${failures} check(s) failed` : "\nAll device-binding checks passed");
await closeDb();
await closeCache();
process.exit(failures ? 1 : 0);
