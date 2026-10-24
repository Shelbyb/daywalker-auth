/**
 * The Account Portal's "Unauthorized sign in" page: default and hosted (/h/<pk>/...) addresses,
 * strict headers, branding, fixed reason messages, and the refusal codes that lead there.
 */
import { eq } from "drizzle-orm";
import { seedInstance } from "./seed";
import { db, closeDb, schema } from "../src/lib/db";
import { closeCache } from "../src/lib/cache";
import { invalidateInstance } from "../src/lib/auth/instance";
import { refusalReason, unauthorizedMessage, unauthorizedUrl, UNAUTHORIZED_REASONS, GENERIC_UNAUTHORIZED } from "../src/lib/auth/unauthorized";

const AUTH = process.env.BASE_URL ?? "http://localhost:3000";
let failures = 0;
const check = (name: string, ok: boolean, detail?: unknown) => {
  console.log(`${ok ? "✓" : "✗"} ${name}${ok ? "" : ` — ${JSON.stringify(detail)?.slice(0, 400)}`}`);
  if (!ok) failures++;
};

// ---------- Reason mapping (no server needed) ----------
check("sign_up_not_allowed → sign_up_restricted", refusalReason("sign_up_not_allowed") === "sign_up_restricted");
check("suspended → account_locked", refusalReason("forbidden", "This account is suspended") === "account_locked");
check("origin refused → origin_not_allowed", refusalReason("forbidden", "Origin not allowed") === "origin_not_allowed");
check("other forbidden errors stay inline", refusalReason("forbidden", "Re-authentication required") === null);
check("wrong password stays inline", refusalReason("invalid_credentials", "Email or password is incorrect") === null);
check("unknown reason → generic message", unauthorizedMessage("nope") === GENERIC_UNAUTHORIZED && unauthorizedMessage(undefined) === GENERIC_UNAUTHORIZED);
check("prototype keys aren't reasons", unauthorizedMessage("__proto__") === GENERIC_UNAUTHORIZED && unauthorizedMessage("toString") === GENERIC_UNAUTHORIZED);
const u = unauthorizedUrl("https://auth.example", "pk_test_x", "account_locked", "https://app.example/x");
check("URL carries only pk, reason and redirect", u.pathname === "/unauthorized-sign-in" && [...u.searchParams.keys()].sort().join() === "pk,reason,redirect_url");

// ---------- The page ----------
const seed = await seedInstance("Unauthorized E2E", ["https://app.example"]);
const { publishableKey: pk, instanceId } = seed;
const [inst] = await db().select().from(schema.instances).where(eq(schema.instances.id, instanceId));
await db().update(schema.instances).set({
  settings: { ...inst.settings, branding: { logoUrl: null, primaryColor: "#123456", backgroundColor: null, title: null }, redirects: { afterSignIn: null, afterSignUp: null, afterLogoClick: "https://app.example/home" } },
}).where(eq(schema.instances.id, instanceId));
await invalidateInstance(instanceId);

const get = async (path: string) => {
  const r = await fetch(`${AUTH}${path}`, { redirect: "manual" });
  return { status: r.status, csp: r.headers.get("content-security-policy") ?? "", html: await r.text() };
};

for (const [label, path] of [["default", `/unauthorized-sign-in?pk=${pk}&reason=account_locked`], ["hosted", `/h/${pk}/unauthorized-sign-in?reason=account_locked`]] as const) {
  const r = await get(path);
  check(`${label}: 200`, r.status === 200, r.status);
  check(`${label}: strict headers (nonce CSP, no framing)`, /'nonce-/.test(r.csp) && r.csp.includes("frame-ancestors 'none'"), r.csp);
  check(`${label}: branding applied`, r.html.includes("#123456"));
  check(`${label}: fixed message for the reason`, r.html.includes(UNAUTHORIZED_REASONS.account_locked.title.replace("'", "&#x27;")) || r.html.includes(UNAUTHORIZED_REASONS.account_locked.title));
  check(`${label}: back-to-sign-in link keeps the instance`, r.html.includes(`/sign-in?pk=${pk}`));
  check(`${label}: afterLogoClick link`, r.html.includes("https://app.example/home"));
}

const unknown = await get(`/unauthorized-sign-in?pk=${pk}&reason=%3Cscript%3Ealert(1)%3C%2Fscript%3E`);
check("unknown reason → generic message, nothing reflected", unknown.status === 200 && unknown.html.includes("You can&#x27;t sign in") && !unknown.html.includes("<script>alert(1)"));
const kept = await get(`/unauthorized-sign-in?pk=${pk}&reason=sign_up_restricted&redirect_url=${encodeURIComponent("https://app.example/after")}`);
check("allow-listed redirect kept on the sign-in link", kept.html.includes(encodeURIComponent("https://app.example/after")));
const evil = await get(`/unauthorized-sign-in?pk=${pk}&redirect_url=${encodeURIComponent("https://evil.example/steal")}`);
// Next's router state echoes the URL; what matters is that no link points there.
check("foreign redirect dropped", ![...evil.html.matchAll(/href="([^"]*)"/g)].some((m) => m[1].includes("evil.example")));
check("missing pk → no instance shown", (await get(`/unauthorized-sign-in?reason=account_locked`)).html.includes("Missing or invalid publishable key"));

// ---------- Refusals from the API carry the codes the components map ----------
const signUp = await fetch(`${AUTH}/v1/client/sign_up`, { method: "POST", headers: { "content-type": "application/json", "x-publishable-key": pk, origin: "https://evil.example" }, body: JSON.stringify({ email: `x.${Date.now()}@example.com`, password: "a long enough password" }) });
const body = (await signUp.json().catch(() => ({}))) as { error?: { code?: string; message?: string } };
check("foreign origin is refused with a code that maps to origin_not_allowed", signUp.status === 403 && refusalReason(body.error?.code ?? "", body.error?.message) === "origin_not_allowed", body);

await closeDb();
await closeCache();
if (failures) {
  console.log(`\n${failures} check(s) failed`);
  process.exit(1);
}
console.log("\nAll unauthorized-page checks passed");
