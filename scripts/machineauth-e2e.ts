/**
 * Machine-to-machine auth (client credentials, scopes, hashed secrets, rotation, JWKS-verifiable tokens) and
 * customer-issued API keys (hashed, prefix, scopes, revoke, last-used, self-service rules), plus the SDK surface.
 */
import { sql } from "drizzle-orm";
import { seedInstance } from "./seed";
import { db, closeDb } from "../src/lib/db";
import { cache, closeCache } from "../src/lib/cache";
import { sha256 } from "../src/lib/ids";
import { createBackendClient, requestMachineToken, verifyApiKey, verifyMachineToken, verifyToken } from "../packages/sdk/src/server";

const AUTH = "http://localhost:3000";
let failures = 0;
const check = (name: string, ok: boolean, detail?: unknown) => {
  console.log(`${ok ? "✓" : "✗"} ${name}${ok ? "" : ` — ${JSON.stringify(detail)?.slice(0, 400)}`}`);
  if (!ok) failures++;
};
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const rows = async (q: ReturnType<typeof sql>) => (await db().execute(q)) as unknown as Record<string, any>[];

const inst = await seedInstance("Machine E2E", ["http://localhost:3001"]);
const { instanceId, publishableKey: pk, secretKey: sk } = inst;
const cfg = { publishableKey: pk, frontendApi: AUTH };
const api = async (method: string, path: string, body?: unknown, key = sk) => {
  const r = await fetch(`${AUTH}/v1/${path}`, { method, headers: { authorization: `Bearer ${key}`, "content-type": "application/json" }, body: body === undefined ? undefined : JSON.stringify(body) });
  return { status: r.status, body: await r.json().catch(() => null) };
};
const tokenReq = (o: { id?: string; secret?: string; body?: Record<string, string>; basic?: boolean; ip?: string; json?: boolean }) => {
  const headers: Record<string, string> = { "x-forwarded-for": o.ip ?? "198.51.100.1" };
  let body: string;
  const fields = { grant_type: "client_credentials", ...(o.basic ? {} : { client_id: o.id ?? "", client_secret: o.secret ?? "" }), ...o.body };
  if (o.json) { headers["content-type"] = "application/json"; body = JSON.stringify(fields); } else { headers["content-type"] = "application/x-www-form-urlencoded"; body = new URLSearchParams(fields).toString(); }
  if (o.basic) headers.authorization = `Basic ${Buffer.from(`${encodeURIComponent(o.id ?? "")}:${encodeURIComponent(o.secret ?? "")}`).toString("base64")}`;
  return fetch(`${AUTH}/v1/m2m/token`, { method: "POST", headers, body }).then(async (r) => ({ status: r.status, body: await r.json().catch(() => null), headers: r.headers }));
};
const resetLimits = async () => { const k = await cache().keys("rl:m2m:*"); if (k.length) await cache().del(...k); };

// ---------- Clients ----------
check("unauthenticated create refused", (await fetch(`${AUTH}/v1/m2m_clients`, { method: "POST", body: "{}" })).status === 401);
const c1 = await api("POST", "m2m_clients", { name: "Worker", scopes: ["read:invoices", "write:invoices"], tokenTtlSeconds: 120 });
check("client created with a secret shown once", c1.status === 201 && /^m2m_/.test(c1.body.id) && /^ms_/.test(c1.body.clientSecret), c1.body);
const secret = c1.body.clientSecret as string, cid = c1.body.id as string;
const stored = await rows(sql`select secret_hash, secret_prefix from m2m_clients where id = ${cid}`);
check("only a hash of the secret is stored", stored[0].secret_hash === sha256(secret) && !JSON.stringify(stored[0]).includes(secret));
check("list/get never return the secret", !JSON.stringify((await api("GET", "m2m_clients")).body).includes(secret) && !JSON.stringify((await api("GET", `m2m_clients/${cid}`)).body).includes(secret));
check("invalid scope string rejected (422)", (await api("POST", "m2m_clients", { name: "x", scopes: ["Bad Scope"] })).status === 422);
check("ttl above max rejected (422)", (await api("POST", "m2m_clients", { name: "x", ttl: 1, tokenTtlSeconds: 99999 })).status === 422);
const other = await seedInstance("Machine E2E other");
check("another instance can't see the client", (await api("GET", `m2m_clients/${cid}`, undefined, other.secretKey)).status === 404);

// ---------- Token endpoint ----------
const t1 = await tokenReq({ id: cid, secret });
check("client credentials (body) issues a token", t1.status === 200 && t1.body.token_type === "Bearer" && t1.body.expires_in === 120 && t1.body.scope === "read:invoices write:invoices", t1.body);
check("response is not cacheable", (t1.headers.get("cache-control") ?? "").includes("no-store"));
const t2 = await tokenReq({ id: cid, secret, basic: true, body: { scope: "read:invoices" } });
check("HTTP Basic works and scope narrows", t2.status === 200 && t2.body.scope === "read:invoices", t2.body);
check("JSON body works", (await tokenReq({ id: cid, secret, json: true })).status === 200);
const wide = await tokenReq({ id: cid, secret, body: { scope: "read:invoices admin" } });
check("scope beyond the client's refused", wide.status === 400 && wide.body.error === "invalid_scope", wide.body);
const gt = await tokenReq({ id: cid, secret, body: { grant_type: "password" } });
check("other grant types refused", gt.status === 400 && gt.body.error === "unsupported_grant_type", gt.body);
const bad = await tokenReq({ id: cid, secret: "ms_wrong" });
const unk = await tokenReq({ id: "m2m_" + "0".repeat(22), secret: "ms_wrong" });
check("wrong secret and unknown client look the same", bad.status === 401 && unk.status === 401 && bad.body.error === "invalid_client" && JSON.stringify(bad.body) === JSON.stringify(unk.body), [bad.body, unk.body]);
check("a user's sk can't be used as client credentials", (await tokenReq({ id: sk, secret: sk })).status === 401);
check("GET not allowed", (await fetch(`${AUTH}/v1/m2m/token`)).status === 405);

// Verification
const tok = t1.body.access_token as string;
const claims = await verifyMachineToken(tok, cfg);
check("verifyMachineToken accepts it against the JWKS", claims?.clientId === cid && claims.scopes.length === 2 && claims.expiresAt - claims.issuedAt === 120, claims);
check("required scopes enforced", !!(await verifyMachineToken(tok, { ...cfg, scopes: ["read:invoices"] })) && (await verifyMachineToken(tok, { ...cfg, scopes: ["admin"] })) === null);
check("narrowed token lacks the other scope", (await verifyMachineToken(t2.body.access_token, { ...cfg, scopes: ["write:invoices"] })) === null);
check("machine token is not a user session token", (await verifyToken(tok, cfg)) === null);
check("tampered token rejected", (await verifyMachineToken(tok.slice(0, -4) + "AAAA", cfg)) === null && (await verifyMachineToken("garbage", cfg)) === null);
check("another instance's key set rejects it", (await verifyMachineToken(tok, { publishableKey: other.publishableKey, frontendApi: AUTH })) === null);
const payload = JSON.parse(Buffer.from(tok.split(".")[1], "base64url").toString());
check("no session id in a machine token", payload.sid === undefined && payload.token_use === "m2m" && payload.aud === payload.iss);
const disc = await (await fetch(`${AUTH}/i/${instanceId}/.well-known/openid-configuration`)).json();
check("discovery lists the token endpoint", disc.token_endpoint === `${AUTH}/v1/m2m/token`, disc);
const sdkTok = await requestMachineToken({ apiUrl: AUTH, clientId: cid, clientSecret: secret, scopes: ["read:invoices"] });
check("SDK requestMachineToken", sdkTok.scopes.join() === "read:invoices" && !!(await verifyMachineToken(sdkTok.accessToken, cfg)));
check("SDK surfaces OAuth errors", await requestMachineToken({ apiUrl: AUTH, clientId: cid, clientSecret: "nope" }).then(() => false, (e) => e.code === "invalid_client"));

// last used
await new Promise((r) => setTimeout(r, 300));
check("last used is recorded", (await rows(sql`select last_used_at from m2m_clients where id = ${cid}`))[0].last_used_at !== null);

// ---------- Rotation ----------
const rot = await api("POST", `m2m_clients/${cid}/rotate_secret`, { graceMinutes: 10 });
check("rotation returns a new secret", rot.status === 200 && rot.body.clientSecret !== secret && rot.body.rotating === true, rot.body);
check("new secret works", (await tokenReq({ id: cid, secret: rot.body.clientSecret })).status === 200);
check("old secret works during the grace period", (await tokenReq({ id: cid, secret })).status === 200);
await rows(sql`update m2m_clients set prev_secret_expires_at = now() - interval '1 minute' where id = ${cid}`);
check("old secret refused after the grace period", (await tokenReq({ id: cid, secret })).status === 401);
const rot2 = await api("POST", `m2m_clients/${cid}/rotate_secret`, {});
check("rotation without grace revokes the old secret at once", rot2.status === 200 && (await tokenReq({ id: cid, secret: rot.body.clientSecret })).status === 401 && (await tokenReq({ id: cid, secret: rot2.body.clientSecret })).status === 200);
check("rotation grace out of range rejected", (await api("POST", `m2m_clients/${cid}/rotate_secret`, { graceMinutes: 99999 })).status === 422);

// Update scopes
await api("PATCH", `m2m_clients/${cid}`, { scopes: ["read:invoices"] });
check("narrowing client scopes applies to new tokens", (await tokenReq({ id: cid, secret: rot2.body.clientSecret, body: { scope: "write:invoices" } })).body.error === "invalid_scope");

// Throttling of failures
await resetLimits();
let blocked = false;
for (let i = 0; i < 14; i++) { const r = await tokenReq({ id: cid, secret: "ms_guess" + i, ip: "198.51.100.77" }); if (r.status === 429) blocked = true; }
check("repeated bad secrets are throttled", blocked);
check("throttling is per source (the real service from another IP still works)", (await tokenReq({ id: cid, secret: rot2.body.clientSecret, ip: "198.51.100.78" })).status === 200);
await resetLimits();

// Delete
const del = await api("DELETE", `m2m_clients/${cid}`);
check("client deleted", del.status === 200 && (await tokenReq({ id: cid, secret: rot2.body.clientSecret })).status === 401);

// ---------- API keys ----------
const email = `ak.${Date.now()}@example.com`, password = "a long enough password";
const clientReq = async (method: string, path: string, o: { body?: unknown; cookie?: string } = {}) => {
  const r = await fetch(`${AUTH}/v1/client/${path}`, { method, headers: { "content-type": "application/json", "x-publishable-key": pk, origin: "http://localhost:3001", "x-forwarded-for": "203.0.113.50", ...(o.cookie ? { cookie: o.cookie } : {}) }, body: method === "GET" ? undefined : JSON.stringify(o.body ?? {}) });
  return { status: r.status, body: await r.json().catch(() => null), cookie: (r.headers.get("set-cookie") ?? "").split(";")[0] };
};
const su = await clientReq("POST", "sign_up", { body: { email, password } });
const cookie = su.cookie, userId = su.body.user.id as string;
check("sign-up for key tests", su.status < 300 && !!cookie, su.body);

check("self-service is off by default", (await clientReq("POST", "api_keys", { cookie, body: { name: "k" } })).body?.error?.code === "api_keys_disabled");
check("self-service list is off by default", (await clientReq("GET", "api_keys", { cookie })).body?.error?.code === "api_keys_disabled");
const bk = await api("POST", "api_keys", { name: "Server made", scopes: ["anything"], userId });
check("backend can create keys for a user regardless", bk.status === 201 && /^ak_test_/.test(bk.body.key) && bk.body.prefix === bk.body.key.slice(0, 12) && bk.body.subject.type === "user", bk.body);
check("both userId and orgId (or neither) refused", (await api("POST", "api_keys", { name: "x", userId, orgId: "org_x" })).status === 400 && (await api("POST", "api_keys", { name: "x" })).status === 400);
check("unknown user refused", (await api("POST", "api_keys", { name: "x", userId: "user_nope" })).status === 404);
const stored2 = await rows(sql`select key_hash, key_prefix from user_api_keys where id = ${bk.body.id}`);
check("only a hash of the key is stored", stored2[0].key_hash === sha256(bk.body.key) && !JSON.stringify(stored2[0]).includes(bk.body.key));
check("list never returns the key", !JSON.stringify((await api("GET", `api_keys?userId=${userId}`)).body).includes(bk.body.key));

const v = await verifyApiKey(bk.body.key, { secretKey: sk, apiUrl: AUTH });
check("verifyApiKey accepts a valid key", v.valid && v.subject.id === userId && v.scopes.join() === "anything", v);
check("verifyApiKey scope check", !(await verifyApiKey(bk.body.key, { secretKey: sk, apiUrl: AUTH, scopes: ["other"] })).valid);
check("another instance can't verify it", !(await verifyApiKey(bk.body.key, { secretKey: other.secretKey, apiUrl: AUTH })).valid);
check("malformed and unknown keys are just invalid", !(await verifyApiKey("ak_test_nope", { secretKey: sk, apiUrl: AUTH })).valid && (await api("POST", "api_keys/verify", { key: 5 })).status === 422);
check("verify requires a secret key", (await fetch(`${AUTH}/v1/api_keys/verify`, { method: "POST", body: JSON.stringify({ key: bk.body.key }) })).status === 401);
await new Promise((r) => setTimeout(r, 300));
check("last used is recorded", (await rows(sql`select last_used_at from user_api_keys where id = ${bk.body.id}`))[0].last_used_at !== null);

// Settings + self-service
check("settings invalid scope rejected (422)", (await api("PATCH", "instance/api_keys", { allowedScopes: ["BAD"] })).status === 422);
const set = await api("PATCH", "instance/api_keys", { enabled: true, allowedScopes: ["read:items"], maxPerSubject: 2, maxExpiryDays: 30 });
check("settings updated", set.status === 200 && set.body.enabled && set.body.maxPerSubject === 2, set.body);
check("self-service needs a scope from the allowed list", (await clientReq("POST", "api_keys", { cookie, body: { name: "k", scopes: ["admin"], expiresInDays: 5 } })).body?.error?.code === "scope_not_allowed");
check("self-service needs an expiry within the limit", (await clientReq("POST", "api_keys", { cookie, body: { name: "k", scopes: ["read:items"] } })).body?.error?.code === "expiry_required" && (await clientReq("POST", "api_keys", { cookie, body: { name: "k", scopes: ["read:items"], expiresInDays: 90 } })).status === 400);
check("signed-out request refused", (await clientReq("POST", "api_keys", { body: { name: "k" } })).status === 401);
check("wrong origin refused (CSRF)", (await fetch(`${AUTH}/v1/client/api_keys`, { method: "POST", headers: { "content-type": "application/json", "x-publishable-key": pk, origin: "https://evil.example", cookie }, body: JSON.stringify({ name: "k" }) })).status === 403);
const mine = await clientReq("POST", "api_keys", { cookie, body: { name: "Laptop", scopes: ["read:items"], expiresInDays: 7 } });
check("user creates their own key", mine.status === 201 && mine.body.key.startsWith("ak_test_") && mine.body.subject.id === userId && !!mine.body.expiresAt, mine.body);
check("another subject can't be requested", (await clientReq("POST", "api_keys", { cookie, body: { name: "k", userId: "user_other", scopes: [], expiresInDays: 1 } })).status === 400);
check("per-subject limit enforced", (await clientReq("POST", "api_keys", { cookie, body: { name: "k3", scopes: [], expiresInDays: 1 } })).status === 403, 0);
const listed = await clientReq("GET", "api_keys", { cookie });
check("user lists only their keys, no secrets", listed.body.data.length === 2 && !JSON.stringify(listed.body).includes(mine.body.key), listed.body);

// Another user can't revoke or see mine
const su2 = await fetch(`${AUTH}/v1/client/sign_up`, { method: "POST", headers: { "content-type": "application/json", "x-publishable-key": pk, origin: "http://localhost:3001", "x-forwarded-for": "203.0.113.51" }, body: JSON.stringify({ email: `ak2.${Date.now()}@example.com`, password }) });
const cookie2 = (su2.headers.get("set-cookie") ?? "").split(";")[0];
check("another user can't revoke my key", (await clientReq("DELETE", `api_keys/${mine.body.id}`, { cookie: cookie2 })).status === 404 && (await verifyApiKey(mine.body.key, { secretKey: sk, apiUrl: AUTH })).valid);
check("another user sees none of my keys", (await clientReq("GET", "api_keys", { cookie: cookie2 })).body.data.length === 0);

// Organization keys
const org = await clientReq("POST", "organizations", { cookie, body: { name: "Keyco" } });
const orgId = org.body.organization?.id;
const ok = await clientReq("POST", "api_keys", { cookie, body: { name: "Org key", orgId, scopes: ["read:items"], expiresInDays: 10 } });
check("org admin creates an org key", ok.status === 201 && ok.body.subject.type === "org" && ok.body.subject.id === orgId, [org.body, ok.body]);
check("non-member can't create or list org keys", (await clientReq("POST", "api_keys", { cookie: cookie2, body: { name: "x", orgId, scopes: [], expiresInDays: 1 } })).status === 404 && (await clientReq("GET", `api_keys?orgId=${orgId}`, { cookie: cookie2 })).status === 404);
const ov = await verifyApiKey(ok.body.key, { secretKey: sk, apiUrl: AUTH });
check("org key verifies with an org subject", ov.valid && ov.subject.type === "org");

// Revoke / expire / ban
const rv = await clientReq("DELETE", `api_keys/${mine.body.id}`, { cookie });
check("user revokes their key; it stops working at once", rv.status === 200 && !!rv.body.revokedAt && !(await verifyApiKey(mine.body.key, { secretKey: sk, apiUrl: AUTH })).valid);
await rows(sql`update user_api_keys set expires_at = now() - interval '1 minute' where id = ${ok.body.id}`);
check("expired key is invalid", !(await verifyApiKey(ok.body.key, { secretKey: sk, apiUrl: AUTH })).valid);
await rows(sql`update users set banned = true where id = ${userId}`);
check("a banned user's key is invalid", !(await verifyApiKey(bk.body.key, { secretKey: sk, apiUrl: AUTH })).valid);
await rows(sql`update users set banned = false where id = ${userId}`);
check("unbanned: valid again", (await verifyApiKey(bk.body.key, { secretKey: sk, apiUrl: AUTH })).valid);
const rb = await api("DELETE", `api_keys/${bk.body.id}`);
check("backend revoke", rb.status === 200 && !(await verifyApiKey(bk.body.key, { secretKey: sk, apiUrl: AUTH })).valid);
await api("DELETE", `users/${userId}`);
check("deleting a user deletes their keys", (await rows(sql`select count(*)::int n from user_api_keys where user_id = ${userId}`))[0].n === 0);

// SDK backend client
const be = createBackendClient({ secretKey: sk, apiUrl: AUTH });
const mc = await be.m2mClients.create({ name: "SDK" , scopes: ["a:b"] });
check("SDK m2mClients", (await be.m2mClients.list()).some((c) => c.id === mc.id) && (await be.m2mClients.rotateSecret(mc.id, 0)).clientSecret !== mc.clientSecret && (await be.m2mClients.delete(mc.id)).deleted);
check("SDK apiKeys.settings", (await be.apiKeys.settings.get()).enabled === true);

const audit = await api("GET", "audit_events?limit=100");
const types = new Set(audit.body.data.map((e: { type: string }) => e.type));
check("audit records client and key lifecycle", ["m2m_client.created", "m2m_client.secret_rotated", "m2m_client.deleted", "user_api_key.created", "user_api_key.revoked"].every((t) => types.has(t)), [...types]);
check("secrets never appear in the audit log", !JSON.stringify(audit.body).includes(secret) && !JSON.stringify(audit.body).includes(bk.body.key));

console.log(failures ? `\n${failures} check(s) failed` : "\nAll machine auth checks passed");
await closeDb();
await closeCache();
process.exit(failures ? 1 : 0);
