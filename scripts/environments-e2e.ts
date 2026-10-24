/**
 * Development vs production instances: separate keys, the dev banner flag, config cloning (what is and isn't
 * copied, secrets re-encrypted, refusals) via the backend API.
 */
import { eq } from "drizzle-orm";
import { seedInstance } from "./seed";
import { db, schema, closeDb } from "../src/lib/db";
import { closeCache } from "../src/lib/cache";
import { createEnvironmentInstance } from "../src/lib/auth/application";
import { encrypt, decrypt } from "../src/lib/crypto";
import { newId } from "../src/lib/ids";
import { createBackendClient } from "../packages/sdk/src/server";

const AUTH = "http://localhost:3000";
let failures = 0;
const check = (name: string, ok: boolean, detail?: unknown) => {
  console.log(`${ok ? "✓" : "✗"} ${name}${ok ? "" : ` — ${JSON.stringify(detail)?.slice(0, 400)}`}`);
  if (!ok) failures++;
};
const api = (sk: string, method: string, path: string, body?: unknown) =>
  fetch(`${AUTH}/v1/${path}`, { method, headers: { authorization: `Bearer ${sk}`, "content-type": "application/json" }, body: body === undefined ? undefined : JSON.stringify(body) }).then(async (r) => ({ status: r.status, body: await r.json().catch(() => null) }));

const dev = await seedInstance("Env E2E");
const prod = await createEnvironmentInstance(dev.accountId, { name: "Env E2E", environment: "production", applicationId: dev.applicationId });
const prodId = prod.instance.id;
const prodSk = prod.secretKey;
check("production keys use live prefixes", prodSk.startsWith("sk_live_") && prod.publishableKey.startsWith("pk_live_") && dev.publishableKey.startsWith("pk_test_"));
check("a second production instance is refused", await createEnvironmentInstance(dev.accountId, { name: "x", environment: "production", applicationId: dev.applicationId }).then(() => false, (e) => e.code === "environment_exists"));
check("another account can't add to the application", await createEnvironmentInstance("acct_other", { name: "x", environment: "production", applicationId: dev.applicationId }).then(() => false, (e) => e.status === 404));

// Keys are separate: dev key is not valid for prod data and vice versa.
const envDev = await api(dev.secretKey, "GET", "instance/environments");
const envProd = await api(prodSk, "GET", "instance/environments");
check("environments lists both, dev first", envDev.body.environments.length === 2 && envDev.body.environments[0].environment === "development" && envDev.body.environment === "development", envDev.body);
check("prod key reports production", envProd.body.environment === "production" && envProd.body.environments.find((e: { current: boolean }) => e.current).instanceId === prodId);
check("secret keys never appear in the listing", !JSON.stringify(envDev.body).includes("sk_"));
const jwks = async (id: string) => (await (await fetch(`${AUTH}/i/${id}/.well-known/jwks.json`)).json()).keys.map((k: { kid: string }) => k.kid);
const [kd, kp] = [await jwks(dev.instanceId), await jwks(prodId)];
check("signing keys are separate", kd.length > 0 && kp.length > 0 && !kd.some((k: string) => kp.includes(k)));

// Banner flag on the public environment endpoint.
const pubEnv = async (pk: string) => (await (await fetch(`${AUTH}/v1/client/environment`, { headers: { "x-publishable-key": pk } })).json()).instanceEnvironment;
check("dev environment reports development", (await pubEnv(dev.publishableKey)) === "development");
check("prod environment reports production", (await pubEnv(prod.publishableKey)) === "production");

// Users never cross.
const email = `u.${Date.now()}@example.com`;
const su = await fetch(`${AUTH}/v1/client/sign_up`, { method: "POST", headers: { "content-type": "application/json", "x-publishable-key": dev.publishableKey, origin: AUTH, "x-forwarded-for": "203.0.113.9" }, body: JSON.stringify({ email, password: "a long enough password" }) });
check("dev sign-up works", su.status === 200 || su.status === 201, su.status);
const prodUsers = await api(prodSk, "GET", "users");
check("dev user not visible in production", prodUsers.status === 200 && prodUsers.body.data.length === 0, prodUsers.body);

// ---------- Set up development config ----------
const [d] = await db().select().from(schema.instances).where(eq(schema.instances.id, dev.instanceId));
await db().update(schema.instances).set({
  settings: { ...d.settings, passwordMinLength: 14, emailCodeSignIn: true, redirects: { afterSignIn: "http://localhost:3001/" }, captchaSiteKey: "devkey", requireTwoFactor: true, branding: { title: "Acme" } },
  allowedOrigins: ["http://localhost:3001", "https://app.example.com"],
}).where(eq(schema.instances.id, dev.instanceId));
await db().insert(schema.oauthProviders).values({ instanceId: dev.instanceId, provider: "github", clientId: "dev-client", clientSecretEnc: encrypt("dev-secret", `oauth_providers.client_secret:${dev.instanceId}:github`), enabled: true });
await db().insert(schema.emailTemplates).values({ instanceId: dev.instanceId, kind: "sign_in", subject: "Hello {{code}}", body: "Code {{code}}" });
await db().insert(schema.orgRoles).values({ instanceId: dev.instanceId, key: "billing", name: "Billing", permissions: ["org:billing:manage"] });
const weId = newId("we");
await db().insert(schema.webhookEndpoints).values({ id: weId, instanceId: dev.instanceId, urlEnc: encrypt("https://example.com/hook", `webhook_endpoints.url:${weId}`), secretEnc: encrypt("whsec_devsecret", `webhook_endpoints.secret:${weId}`), events: ["user.created"] });
await fetch(`${AUTH}/v1/instance/environments`, { headers: { authorization: `Bearer ${dev.secretKey}` } }); // warm
const { invalidateInstance } = await import("../src/lib/auth/instance");
await invalidateInstance(dev.instanceId);

// ---------- Refusals ----------
check("clone with the dev key refused", (await api(dev.secretKey, "POST", "instance/clone", {})).body?.error?.code === "clone_target_not_production");
check("unauthenticated clone refused", (await fetch(`${AUTH}/v1/instance/clone`, { method: "POST", body: "{}" })).status === 401);
check("secrets for a part that isn't copied refused", (await api(prodSk, "POST", "instance/clone", { include: { webhooks: false }, copySecrets: ["webhooks"] })).body?.error?.code === "secrets_without_part");
check("unknown fields rejected (422)", (await api(prodSk, "POST", "instance/clone", { includeUsers: true })).status === 422);

// ---------- Clone without secrets ----------
const r1 = await api(prodSk, "POST", "instance/clone", {});
check("clone succeeds", r1.status === 200 && r1.body.secretsCopied.length === 0, r1.body);
const [p] = await db().select().from(schema.instances).where(eq(schema.instances.id, prodId));
const ps = p.settings as Record<string, unknown>;
check("settings copied", ps.passwordMinLength === 14 && ps.emailCodeSignIn === true && (ps.branding as { title: string }).title === "Acme", ps);
check("redirects, captcha key and required 2FA not copied", ps.redirects === undefined && ps.captchaSiteKey === undefined && ps.requireTwoFactor === undefined, ps);
check("skipped reports why", r1.body.skipped.some((s: { what: string }) => s.what === "settings.requireTwoFactor"));
check("origins not copied by default", p.allowedOrigins.length === 0);
const pp = await db().select().from(schema.oauthProviders).where(eq(schema.oauthProviders.instanceId, prodId));
check("provider created disabled with an empty secret", pp.length === 1 && !pp[0].enabled && pp[0].clientId === "dev-client" && decrypt(pp[0].clientSecretEnc, `oauth_providers.client_secret:${prodId}:github`) === "");
check("template copied", (await db().select().from(schema.emailTemplates).where(eq(schema.emailTemplates.instanceId, prodId))).length === 1);
check("role copied", (await db().select().from(schema.orgRoles).where(eq(schema.orgRoles.instanceId, prodId))).some((r) => r.key === "billing"));
check("webhooks not copied by default", (await db().select().from(schema.webhookEndpoints).where(eq(schema.webhookEndpoints.instanceId, prodId))).length === 0);
check("no users copied", (await db().select().from(schema.users).where(eq(schema.users.instanceId, prodId))).length === 0);
check("no extra secret keys copied", (await db().select().from(schema.apiKeys).where(eq(schema.apiKeys.instanceId, prodId))).length === 1);
const dsk = await fetch(`${AUTH}/v1/users`, { headers: { authorization: `Bearer ${dev.secretKey}` } });
check("dev key still scoped to dev", dsk.status === 200);
const enableEmpty = await db().select().from(schema.oauthProviders).where(eq(schema.oauthProviders.instanceId, prodId));
check("production enabled-provider list excludes it", !(await (await fetch(`${AUTH}/v1/client/environment`, { headers: { "x-publishable-key": prod.publishableKey } })).json()).oauthProviders.includes("github") && enableEmpty.length === 1);

// ---------- Clone with webhooks + origins, no secrets ----------
const r2 = await api(prodSk, "POST", "instance/clone", { include: { webhooks: true, origins: true, providers: true } });
const pw = await db().select().from(schema.webhookEndpoints).where(eq(schema.webhookEndpoints.instanceId, prodId));
check("webhook created disabled with a new secret", r2.status === 200 && pw.length === 1 && !pw[0].enabled && r2.body.webhookSecrets.length === 1 && r2.body.webhookSecrets[0].secret !== "whsec_devsecret" && decrypt(pw[0].secretEnc, `webhook_endpoints.secret:${pw[0].id}`) === r2.body.webhookSecrets[0].secret, r2.body);
check("webhook URL re-encrypted for the new row", decrypt(pw[0].urlEnc, `webhook_endpoints.url:${pw[0].id}`) === "https://example.com/hook");
const [p2] = await db().select().from(schema.instances).where(eq(schema.instances.id, prodId));
check("only non-localhost origins copied", JSON.stringify(p2.allowedOrigins) === '["https://app.example.com"]', p2.allowedOrigins);
check("existing provider left alone on re-clone", r2.body.skipped.some((s: { what: string }) => s.what === "provider github"));
const r3 = await api(prodSk, "POST", "instance/clone", { include: { webhooks: true } });
check("re-cloning doesn't duplicate webhooks", (await db().select().from(schema.webhookEndpoints).where(eq(schema.webhookEndpoints.instanceId, prodId))).length === 1 && r3.body.copied.webhooks.length === 0);

// ---------- Clone with secrets ----------
await db().delete(schema.oauthProviders).where(eq(schema.oauthProviders.instanceId, prodId));
await db().delete(schema.webhookEndpoints).where(eq(schema.webhookEndpoints.instanceId, prodId));
const r4 = await api(prodSk, "POST", "instance/clone", { include: { webhooks: true }, copySecrets: ["providers", "webhooks"] });
const [pp2] = await db().select().from(schema.oauthProviders).where(eq(schema.oauthProviders.instanceId, prodId));
const [pw2] = await db().select().from(schema.webhookEndpoints).where(eq(schema.webhookEndpoints.instanceId, prodId));
check("provider secret copied and re-encrypted for production", r4.status === 200 && decrypt(pp2.clientSecretEnc, `oauth_providers.client_secret:${prodId}:github`) === "dev-secret" && pp2.enabled);
const [pdev] = await db().select().from(schema.oauthProviders).where(eq(schema.oauthProviders.instanceId, dev.instanceId));
check("ciphertext differs from the source (not copied as-is)", pdev.clientSecretEnc !== pp2.clientSecretEnc);
check("webhook secret copied; no secrets returned", decrypt(pw2.secretEnc, `webhook_endpoints.secret:${pw2.id}`) === "whsec_devsecret" && r4.body.webhookSecrets.length === 0 && !pw2.enabled);
check("response never contains the provider secret", !JSON.stringify(r4.body).includes("dev-secret"));
const audit = await api(prodSk, "GET", "audit_events?type=instance.config_cloned");
check("clone is audited", audit.body?.data?.length >= 3, audit.body);

// SDK surface
const sdk = createBackendClient({ secretKey: prodSk, apiUrl: AUTH });
check("SDK environments.get", (await sdk.environments.get()).environment === "production");
check("SDK cloneFromDevelopment", (await sdk.environments.cloneFromDevelopment({ include: { templates: true } })).to.instanceId === prodId);

console.log(failures ? `\n${failures} check(s) failed` : "\nAll environment checks passed");
await closeDb();
await closeCache();
process.exit(failures ? 1 : 0);
