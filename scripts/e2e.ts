/** End-to-end checks against a running server (BASE_URL, default http://localhost:3000). */
import { createRemoteJWKSet, jwtVerify } from "jose";
import { seedInstance } from "./seed";
import { db, closeDb } from "../src/lib/db";
import { closeCache } from "../src/lib/cache";
import { encrypt, decrypt } from "../src/lib/crypto";
import { sql } from "drizzle-orm";

const BASE = process.env.BASE_URL ?? "http://localhost:3000";
let failures = 0;
const check = (name: string, ok: boolean, detail?: unknown) => {
  console.log(`${ok ? "✓" : "✗"} ${name}${ok ? "" : ` — ${JSON.stringify(detail)}`}`);
  if (!ok) failures++;
};

const { instanceId, publishableKey: pk, secretKey: sk } = await seedInstance("E2E", []);
const email = `ada.${Date.now()}@example.com`;
let cookie = "";

async function client(path: string, init: RequestInit & { origin?: string } = {}) {
  const res = await fetch(`${BASE}/v1/client/${path}`, {
    ...init,
    headers: {
      "content-type": "application/json",
      "x-publishable-key": pk,
      origin: init.origin ?? BASE,
      ...(cookie ? { cookie } : {}),
    },
  });
  const sc = res.headers.get("set-cookie");
  if (sc) cookie = sc.split(";")[0];
  return { res, body: res.status === 204 ? null : await res.json(), setCookie: sc };
}
const backend = (path: string, key = sk, init: RequestInit = {}) =>
  fetch(`${BASE}/v1/${path}`, { ...init, headers: { authorization: `Bearer ${key}` } });

// Sign up
const su = await client("sign_up", { method: "POST", body: JSON.stringify({ email, password: "correct horse battery", firstName: "Ada" }) });
check("sign-up returns 201 + JWT", su.res.status === 201 && !!su.body.jwt, su.body);
check("refresh cookie is HttpOnly and path-scoped", /HttpOnly/i.test(su.setCookie ?? "") && /Path=\/v1\/client/.test(su.setCookie ?? ""), su.setCookie);
check("response never includes password data", !JSON.stringify(su.body).includes("hash"));

// JWT verifies against published JWKS
const iss = `${BASE}/i/${instanceId}`;
const jwks = createRemoteJWKSet(new URL(`${iss}/.well-known/jwks.json`));
const { payload, protectedHeader } = await jwtVerify(su.body.jwt, jwks, { issuer: iss });
check("JWT verifies via JWKS (ES256, correct sub/sid)", protectedHeader.alg === "ES256" && payload.sub === su.body.user.id && payload.sid === su.body.sessionId);
check("JWT lifetime is 60s", (payload.exp! - payload.iat!) === 60);
const jwksBody = await (await fetch(`${iss}/.well-known/jwks.json`)).json();
check("JWKS exposes no private key material", !JSON.stringify(jwksBody).includes('"d"'));

// Duplicate + validation
const savedCookie = cookie;
const dup = await client("sign_up", { method: "POST", body: JSON.stringify({ email: email.toUpperCase(), password: "another password" }) });
check("duplicate email (case-insensitive) → 409", dup.res.status === 409, dup.body);
const short = await client("sign_up", { method: "POST", body: JSON.stringify({ email: "x" + email, password: "short" }) });
check("short password → 400", short.res.status === 400, short.body);
cookie = savedCookie;

// Encryption at rest
const rows = await db().execute(sql`select email_enc, email_index from email_addresses where instance_id = ${instanceId}`);
const raw = JSON.stringify(rows);
check("email not stored in plaintext", !raw.includes(email) && !raw.includes("example.com"));
const u = await db().execute(sql`select first_name_enc from users where instance_id = ${instanceId}`);
check("first name not stored in plaintext", !JSON.stringify(u).includes("Ada"));
const s = await db().execute(sql`select refresh_token_hash, user_agent_enc, ip_address_enc from sessions where instance_id = ${instanceId}`);
check("refresh token stored only as hash", !JSON.stringify(s).includes(cookie.split("=")[1]));
const ct = encrypt("secret", "users.first_name:user_a");
let swapped = false;
try { decrypt(ct, "users.first_name:user_b"); swapped = true; } catch {}
check("ciphertext moved to another row fails to decrypt (AAD)", !swapped);

// Sign in
const bad = await client("sign_in", { method: "POST", body: JSON.stringify({ email, password: "wrong password" }) });
check("wrong password → 400 generic message", bad.res.status === 400 && bad.body.error.code === "invalid_credentials");
const unknown = await client("sign_in", { method: "POST", body: JSON.stringify({ email: "nobody@example.com", password: "wrong password" }) });
check("unknown email → same error as wrong password", unknown.body.error.code === bad.body.error.code && unknown.body.error.message === bad.body.error.message);
const si = await client("sign_in", { method: "POST", body: JSON.stringify({ email, password: "correct horse battery" }) });
check("correct password → 200", si.res.status === 200 && !!si.body.jwt, si.body);

// Refresh + session
const tok = await client("session/token", { method: "POST" });
check("token refresh returns new JWT", tok.res.status === 200 && !!tok.body.jwt, tok.body);
const me = await client("session", { method: "GET" });
check("current session returns decrypted user", me.body.user?.emailAddresses?.[0]?.email === email, me.body);

// CSRF / origin
const evil = await client("session/token", { method: "POST", origin: "https://evil.example" });
check("foreign origin rejected → 403", evil.res.status === 403);
check("no CORS grant to foreign origin", !evil.res.headers.get("access-control-allow-origin"));

// Backend API
const list = await backend("users");
const lb = await list.json();
check("backend lists users with decrypted email", list.status === 200 && lb.data[0]?.emailAddresses[0]?.email === email, lb);
check("bad secret key → 401", (await backend("users", "sk_test_nope")).status === 401);
check("publishable key can't call backend API", (await backend("users", pk)).status === 401);

// Revoke via backend → refresh fails
const rv = await backend(`sessions/${si.body.sessionId}/revoke`, sk, { method: "POST" });
check("backend revoke → 200", rv.status === 200);
const after = await client("session/token", { method: "POST" });
check("revoked session can't mint tokens", after.res.status === 401, after.body);

// Sign in again, then sign out
await client("sign_in", { method: "POST", body: JSON.stringify({ email, password: "correct horse battery" }) });
const out = await client("session", { method: "DELETE" });
check("sign-out clears cookie", out.res.status === 200 && /Max-Age=0/i.test(out.setCookie ?? ""));

// Rate limit (per account): 10 per 15 min, 2 successful attempts already used above + 1 bad
let limited = false;
for (let i = 0; i < 12; i++) {
  const r = await client("sign_in", { method: "POST", body: JSON.stringify({ email, password: "wrong password" }) });
  if (r.res.status === 429) { limited = true; break; }
}
check("brute force is rate limited → 429", limited);

// Headers
const h = (await fetch(`${BASE}/sign-in?pk=${pk}`)).headers;
check("security headers set (CSP, frame-ancestors, nosniff)", !!h.get("content-security-policy")?.includes("frame-ancestors 'none'") && h.get("x-content-type-options") === "nosniff" && h.get("x-frame-options") === "DENY");
const ah = (await backend("users")).headers;
check("API responses are no-store", ah.get("cache-control")?.includes("no-store") ?? false);

await closeDb();
await closeCache();
console.log(failures ? `\n${failures} check(s) failed` : "\nAll checks passed");
process.exit(failures ? 1 : 0);
