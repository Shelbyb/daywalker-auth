/**
 * SDK checks: server verification, backend client, and the example app's protection.
 * Needs the auth service on :3000 and examples/nextjs on :3001.
 */
import { verifyToken, createBackendClient } from "@daywalker/auth/server";
import { instanceIdFromKey } from "@daywalker/auth";
import { cache, closeCache } from "../src/lib/cache";

const AUTH = "http://localhost:3000";
const APP = "http://localhost:3001";
const pk = process.env.NEXT_PUBLIC_DAYWALKER_PUBLISHABLE_KEY!;
const sk = process.env.DAYWALKER_SECRET_KEY!;
let failures = 0;
const check = (name: string, ok: boolean, detail?: unknown) => {
  console.log(`${ok ? "✓" : "✗"} ${name}${ok ? "" : ` — ${JSON.stringify(detail)}`}`);
  if (!ok) failures++;
};

// Test setup: this suite reuses the example app's instance (its keys are baked into the app at
// build time), so repeated runs eventually hit the real sign-up limit (10/hour per IP).
// Clear only that instance's sign-up buckets; the limit itself stays in force.
{
  const stream = cache().scanStream({ match: `rl:${instanceIdFromKey(pk)}:sign_up:*`, count: 100 });
  for await (const keys of stream) if ((keys as string[]).length) await cache().del(...(keys as string[]));
}

// Sign up as the example app's origin would
const email = `grace.${Date.now()}@example.com`;
const su = await fetch(`${AUTH}/v1/client/sign_up`, {
  method: "POST",
  headers: { "content-type": "application/json", "x-publishable-key": pk, origin: APP },
  body: JSON.stringify({ email, password: "a long passphrase here", firstName: "Grace" }),
});
const { jwt, user } = await su.json();
check("CORS grants the allow-listed app origin", su.headers.get("access-control-allow-origin") === APP);

const cfg = { publishableKey: pk, frontendApi: AUTH };
const claims = await verifyToken(jwt, { ...cfg, authorizedParties: [APP] });
check("verifyToken accepts a valid token", claims?.userId === user.id && claims?.azp === APP, claims);
check("verifyToken rejects a tampered token", (await verifyToken(jwt.slice(0, -4) + "AAAA", cfg)) === null);
const [h, p, s] = jwt.split(".");
const forged = [h, Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(p, "base64url").toString()), sub: "user_attacker" })).toString("base64url"), s].join(".");
check("verifyToken rejects a modified payload", (await verifyToken(forged, cfg)) === null);
const none = `${Buffer.from('{"alg":"none"}').toString("base64url")}.${p}.`;
check("verifyToken rejects alg=none", (await verifyToken(none, cfg)) === null);
check("verifyToken rejects tokens minted for another app (azp)", (await verifyToken(jwt, { ...cfg, authorizedParties: ["https://other.app"] })) === null);
check("verifyToken returns null for garbage", (await verifyToken("not.a.jwt", cfg)) === null && (await verifyToken(undefined, cfg)) === null);
check("instanceIdFromKey rejects bad keys", (() => { try { instanceIdFromKey("pk_test_bad"); return false; } catch { return true; } })());

const be = createBackendClient({ secretKey: sk, apiUrl: AUTH });
check("backend client fetches the user", (await be.users.get(user.id)).emailAddresses[0].email === email);
check("backend client refuses a publishable key", (() => { try { createBackendClient({ secretKey: pk, apiUrl: AUTH }); return false; } catch { return true; } })());

// Example app protection
const r1 = await fetch(`${APP}/dashboard`, { redirect: "manual" });
const loc = r1.headers.get("location") ?? "";
check("signed-out page visit redirects to hosted sign-in with return URL", r1.status === 307 && loc.startsWith(`${AUTH}/sign-in?pk=`) && loc.includes(encodeURIComponent(`${APP}/dashboard`)), { s: r1.status, loc });
const r2 = await fetch(`${APP}/dashboard`, { redirect: "manual", headers: { cookie: "__dw_active=1" } });
const html2 = await r2.text();
check("expired token + active flag serves refresh page instead of bouncing", r2.status === 200 && html2.includes("/v1/client/session/token"));
const r3 = await fetch(`${APP}/dashboard`, { headers: { cookie: `__dw_session=${jwt}` } });
const html3 = await r3.text();
check("valid session cookie renders the protected server page", r3.status === 200 && html3.includes(email), r3.status);
check("forged cookie is not accepted", (await fetch(`${APP}/dashboard`, { redirect: "manual", headers: { cookie: `__dw_session=${forged}` } })).status === 307);
check("protected API without token → 401", (await fetch(`${APP}/api/me`)).status === 401);
const r5 = await fetch(`${APP}/api/me`, { headers: { authorization: `Bearer ${jwt}` } });
check("protected API with Bearer token → userId", (await r5.json()).userId === user.id);

// Hosted page redirect validation
const ok = await (await fetch(`${AUTH}/sign-in?pk=${pk}&redirect_url=${encodeURIComponent(`${APP}/dashboard`)}`)).text();
const evil = await (await fetch(`${AUTH}/sign-in?pk=${pk}&redirect_url=${encodeURIComponent("https://evil.example/phish")}`)).text();
const proto = await (await fetch(`${AUTH}/sign-in?pk=${pk}&redirect_url=${encodeURIComponent("javascript:alert(1)")}`)).text();
// Inspect the `redirect` prop handed to the form (the page's own URL also appears in Next's router state).
// React serializes an omitted (undefined) prop as "$undefined".
const prop = (html: string) => {
  const v = html.match(/redirect\\":\\"([^\\"]*)/)?.[1] ?? null;
  return v === "$undefined" ? null : v;
};
check("hosted page keeps an allow-listed redirect", prop(ok) === `${APP}/dashboard`, prop(ok));
check("hosted page drops a foreign redirect (no open redirect)", prop(evil) === null, prop(evil));
check("hosted page drops javascript: redirects", prop(proto) === null, prop(proto));

await closeCache();
console.log(failures ? `\n${failures} check(s) failed` : "\nAll SDK checks passed");
process.exit(failures ? 1 : 0);
