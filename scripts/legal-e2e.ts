/** Terms-acceptance checks (email sign-up). OAuth consent is covered in oauth-e2e. */
import { sql } from "drizzle-orm";
import { seedInstance } from "./seed";
import { db, closeDb } from "../src/lib/db";
import { closeCache } from "../src/lib/cache";

const AUTH = "http://localhost:3000";
let failures = 0;
const check = (name: string, ok: boolean, detail?: unknown) => {
  console.log(`${ok ? "✓" : "✗"} ${name}${ok ? "" : ` — ${JSON.stringify(detail)}`}`);
  if (!ok) failures++;
};
const { publishableKey: pk, secretKey: sk } = await seedInstance("Legal E2E", []);
const post = async (path: string, body: unknown) => {
  const r = await fetch(`${AUTH}/v1/client/${path}`, { method: "POST", headers: { "content-type": "application/json", "x-publishable-key": pk, origin: AUTH }, body: JSON.stringify(body) });
  return { status: r.status, body: await r.json() };
};
const setLegal = (body: unknown) => fetch(`${AUTH}/v1/instance/legal`, { method: "PUT", headers: { authorization: `Bearer ${sk}`, "content-type": "application/json" }, body: JSON.stringify(body) });
const env = async () => (await (await fetch(`${AUTH}/v1/client/environment?pk=${pk}`)).json()).legal;
const t = Date.now();

check("off by default", (await env()).required === false);
check("sign-up works without consent while off", (await post("sign_up", { email: `a.${t}@example.com`, password: "a good password" })).status === 201);
check("required without termsUrl rejected", (await setLegal({ required: true, termsUrl: null, privacyUrl: null, version: "1" })).status === 422);
check("non-HTTPS terms URL rejected", (await setLegal({ required: true, termsUrl: "http://example.com/terms", privacyUrl: null, version: "1" })).status === 422);
check("publishable key can't change terms", (await fetch(`${AUTH}/v1/instance/legal`, { method: "PUT", headers: { authorization: `Bearer ${pk}` } })).status === 401);
check("turn on required acceptance", (await setLegal({ required: true, termsUrl: "https://example.com/terms", privacyUrl: "https://example.com/privacy", version: "2026-10-21" })).status === 200);
const e = await env();
check("environment reflects settings immediately", e.required === true && e.termsUrl === "https://example.com/terms" && e.version === "2026-10-21", e);

check("sign-up without consent → legal_required", (await post("sign_up", { email: `b.${t}@example.com`, password: "a good password" })).body.error?.code === "legal_required");
check("sign-up with legalAccepted:false → legal_required", (await post("sign_up", { email: `b.${t}@example.com`, password: "a good password", legalAccepted: false })).body.error?.code === "legal_required");
const ok = await post("sign_up", { email: `b.${t}@example.com`, password: "a good password", legalAccepted: true });
check("sign-up with consent → created", ok.status === 201, ok.body);
const rows = await db().execute(sql`select version, method from legal_acceptances where user_id = ${ok.body.user.id}`);
check("acceptance recorded with version + method", rows.length === 1 && rows[0].version === "2026-10-21" && rows[0].method === "password", rows);
check("existing users sign in without re-accepting", (await post("sign_in", { email: `a.${t}@example.com`, password: "a good password" })).body.status === "complete");

await setLegal({ required: true, termsUrl: "https://example.com/terms", privacyUrl: null, version: "v2" });
const v2 = await post("sign_up", { email: `c.${t}@example.com`, password: "a good password", legalAccepted: true });
check("new version recorded after a bump", (await db().execute(sql`select version from legal_acceptances where user_id = ${v2.body.user.id}`))[0]?.version === "v2");

const signUpPage = await (await fetch(`${AUTH}/sign-up?pk=${pk}`)).text();
const signInPage = await (await fetch(`${AUTH}/sign-in?pk=${pk}`)).text();
check("hosted sign-up shows the consent checkbox with the terms link", signUpPage.includes("I agree to the") && signUpPage.includes("https://example.com/terms"));
check("hosted sign-in doesn't", !signInPage.includes("I agree to the"));
check("platform Terms of Service page is published", (await fetch(`${AUTH}/docs/legal/terms`)).status === 200);

await closeDb();
await closeCache();
console.log(failures ? `\n${failures} check(s) failed` : "\nAll terms checks passed");
process.exit(failures ? 1 : 0);
