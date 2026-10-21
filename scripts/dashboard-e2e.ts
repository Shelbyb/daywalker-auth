/**
 * Dashboard data-layer checks: ownership isolation, keys, settings, providers, users.
 * Calls the lib directly (the same functions the dashboard's server actions call) and the
 * running service on :3000 for effects.
 */
import { sql } from "drizzle-orm";
import { seedInstance } from "./seed";
import { db, schema, closeDb } from "../src/lib/db";
import { closeCache } from "../src/lib/cache";
import { newId } from "../src/lib/ids";
import { ApiError } from "../src/lib/http";

const AUTH = "http://localhost:3000";
let failures = 0;
const check = (name: string, ok: boolean, detail?: unknown) => {
  console.log(`${ok ? "✓" : "✗"} ${name}${ok ? "" : ` — ${JSON.stringify(detail)}`}`);
  if (!ok) failures++;
};

// Make the dashboard "enabled" with a throwaway platform instance, before the lib reads env.
const platform = await seedInstance("Platform (test)", [AUTH]);
process.env.PLATFORM_PUBLISHABLE_KEY = platform.publishableKey;
const D = await import("../src/lib/dashboard");

const status = async (fn: () => Promise<unknown>) => {
  try {
    await fn();
    return 0;
  } catch (e) {
    return e instanceof ApiError ? e.status : -1;
  }
};
const errMsg = async (fn: () => Promise<unknown>) => {
  try {
    await fn();
    return "";
  } catch (e) {
    return (e as Error).message;
  }
};
const front = (pk: string, path: string, body: unknown) =>
  fetch(`${AUTH}/v1/client/${path}`, { method: "POST", headers: { "content-type": "application/json", "x-publishable-key": pk, origin: AUTH, "x-forwarded-for": `198.51.100.${Math.floor(Math.random() * 250) + 1}` }, body: JSON.stringify(body) }).then(async (r) => ({ status: r.status, body: await r.json() }));
const backend = (sk: string) => fetch(`${AUTH}/v1/users?limit=1`, { headers: { authorization: `Bearer ${sk}` } }).then((r) => r.status);

const alice = `user_alice${Date.now()}`, bob = `user_bob${Date.now()}`;

// ---------- Accounts ----------
const accA = await D.ensureAccount(alice);
check("account created on first visit and reused after", accA === (await D.ensureAccount(alice)));
check("each developer gets a separate account", accA !== (await D.ensureAccount(bob)));

// ---------- Instances ----------
const dev = await D.createInstance(alice, { name: "  Acme (dev)  ", environment: "development" });
check("dev instance → pk_test / sk_test keys", dev.publishableKey.startsWith("pk_test_") && dev.secretKey.startsWith("sk_test_"));
check("the new secret key works against the backend API", (await backend(dev.secretKey)) === 200);
const prod = await D.createInstance(alice, { name: "Acme", environment: "production" });
check("production instance → pk_live / sk_live keys", prod.publishableKey.startsWith("pk_live_") && prod.secretKey.startsWith("sk_live_"));
check("blank name rejected", (await errMsg(() => D.createInstance(alice, { name: "   ", environment: "development" }))).length > 0);
check("name is trimmed", (await D.instanceDetails(alice, dev.id)).name === "Acme (dev)");
const keyRows = await db().execute(sql`select key_hash from api_keys where instance_id = ${dev.id}`);
check("secret keys are stored hashed only", keyRows.length === 1 && !JSON.stringify(keyRows).includes(dev.secretKey.slice(8)));
for (let i = 0; i < 3; i++) await D.createInstance(alice, { name: `Extra ${i}`, environment: "development" });
check("instance quota enforced (5)", (await status(() => D.createInstance(alice, { name: "One too many", environment: "development" }))) === 400);
check("listInstances shows only mine", (await D.listInstances(alice)).length === 5 && (await D.listInstances(bob)).length === 0);

// ---------- Isolation: Bob can touch nothing of Alice's ----------
const targets: [string, () => Promise<unknown>][] = [
  ["details", () => D.instanceDetails(bob, dev.id)],
  ["list keys", () => D.listKeys(bob, dev.id)],
  ["create key", () => D.createKey(bob, dev.id, "evil")],
  ["revoke key", () => D.revokeKey(bob, dev.id, "sk_x")],
  ["settings", () => D.updateSettings(bob, dev.id, { name: "pwned", allowedOrigins: [], passwordMinLength: 8, sessionLifetimeDays: 7 })],
  ["terms", () => D.updateLegal(bob, dev.id, { required: false, termsUrl: null, privacyUrl: null, version: "1" })],
  ["providers list", () => D.listProviders(bob, dev.id)],
  ["save provider", () => D.saveProvider(bob, dev.id, "github", { clientId: "x", clientSecret: "y", enabled: true })],
  ["list users", () => D.listUsers(bob, dev.id)],
  ["ban user", () => D.banUser(bob, dev.id, "user_x", true)],
  ["delete user", () => D.removeUser(bob, dev.id, "user_x")],
  ["delete instance", () => D.deleteInstance(bob, dev.id, "Acme (dev)")],
];
for (const [label, fn] of targets) check(`other developer gets 404 on: ${label}`, (await status(fn)) === 404);
check("nonexistent instance is also 404 (no existence leak)", (await status(() => D.instanceDetails(alice, "ins_doesnotexist0000000000"))) === 404);

// The platform instance itself can never be managed from the dashboard.
const [platAcc] = await db().select({ a: schema.instances.accountId }).from(schema.instances).where(sql`id = ${Buffer.from(platform.publishableKey.split("_")[2], "base64url").toString()}`);
await db().insert(schema.accountMembers).values({ accountId: platAcc.a, userId: alice });
check("platform instance is excluded even for a member of its account", (await status(() => D.instanceDetails(alice, platform.instanceId))) === 404);

// ---------- Keys ----------
const second = await D.createKey(alice, dev.id, "CI");
check("extra key works", (await backend(second)) === 200);
const keys = await D.listKeys(alice, dev.id);
check("listing shows prefixes, never full keys", keys.length === 2 && !JSON.stringify(keys).includes(second.slice(12)));
await D.revokeKey(alice, dev.id, keys.find((k) => k.name === "CI")!.id);
check("revoked key stops working immediately (cache purged)", (await backend(second)) === 401);
check("the other key still works", (await backend(dev.secretKey)) === 200);
check("revoking twice → 404", (await status(() => D.revokeKey(alice, dev.id, keys.find((k) => k.name === "CI")!.id))) === 404);

// ---------- Settings ----------
check("http origin (non-localhost) rejected", (await status(() => D.updateSettings(alice, dev.id, { name: "A", allowedOrigins: ["http://example.com"], passwordMinLength: 8, sessionLifetimeDays: 7 }))) === 400);
check("garbage origin rejected", (await status(() => D.updateSettings(alice, dev.id, { name: "A", allowedOrigins: ["*"], passwordMinLength: 8, sessionLifetimeDays: 7 }))) === 400);
check("password minimum below 8 rejected", (await errMsg(() => D.updateSettings(alice, dev.id, { name: "A", allowedOrigins: [], passwordMinLength: 4, sessionLifetimeDays: 7 }))).length > 0);
await D.updateSettings(alice, dev.id, { name: "Acme (dev)", allowedOrigins: ["https://App.Example.com/some/path", "http://localhost:3001", "https://app.example.com"], passwordMinLength: 14, sessionLifetimeDays: 3 });
const after = await D.instanceDetails(alice, dev.id);
check("origins normalized and de-duplicated", JSON.stringify(after.allowedOrigins) === JSON.stringify(["https://app.example.com", "http://localhost:3001"]), after.allowedOrigins);
const short = await front(dev.publishableKey, "sign_up", { email: `s.${Date.now()}@example.com`, password: "only 12 char" });
check("new password minimum applies to sign-ups immediately", short.body.error?.code === "password_too_short", short.body);

// ---------- Terms ----------
check("terms required without a URL rejected", (await errMsg(() => D.updateLegal(alice, dev.id, { required: true, termsUrl: null, privacyUrl: null, version: "1" }))).length > 0);
await D.updateLegal(alice, dev.id, { required: true, termsUrl: "https://example.com/terms", privacyUrl: null, version: "v1" });
const noTerms = await front(dev.publishableKey, "sign_up", { email: `t.${Date.now()}@example.com`, password: "a long enough password" });
check("terms setting enforced on sign-up immediately", noTerms.body.error?.code === "legal_required", noTerms.body);
await D.updateLegal(alice, dev.id, { required: false, termsUrl: null, privacyUrl: null, version: "v1" });

// ---------- Providers ----------
check("unknown provider 404", (await status(() => D.saveProvider(alice, dev.id, "myspace", { clientId: "x", clientSecret: "y", enabled: true }))) === 404);
await D.saveProvider(alice, dev.id, "github", { clientId: "gh-client", clientSecret: "super-secret-value", enabled: true });
const provs = await D.listProviders(alice, dev.id);
check("provider listed, secret never returned", provs.find((p) => p.provider === "github")?.configured === true && !JSON.stringify(provs).includes("super-secret"));
const enc = await db().execute(sql`select client_secret_enc from oauth_providers where instance_id = ${dev.id}`);
check("client secret encrypted at rest", String(enc[0].client_secret_enc).startsWith("v1.") && !String(enc[0].client_secret_enc).includes("super-secret"));
const env1 = await (await fetch(`${AUTH}/v1/client/environment?pk=${dev.publishableKey}`)).json();
check("enabled provider appears in the environment", env1.oauthProviders?.includes("github"), env1);
await D.setProviderEnabled(alice, dev.id, "github", false);
const env2 = await (await fetch(`${AUTH}/v1/client/environment?pk=${dev.publishableKey}`)).json();
check("disabling takes effect immediately", !env2.oauthProviders?.includes("github"), env2);

// ---------- Users ----------
await D.updateSettings(alice, dev.id, { name: "Acme (dev)", allowedOrigins: [], passwordMinLength: 8, sessionLifetimeDays: 7 });
const email = `member.${Date.now()}@example.com`;
const su = await front(dev.publishableKey, "sign_up", { email, password: "a long enough password" });
const uid = su.body.user.id as string;
const list = await D.listUsers(alice, dev.id);
check("user appears in the dashboard list", list.some((u) => u.id === uid && u.email === email && u.banned === false));
await D.banUser(alice, dev.id, uid, true);
check("suspended user can't sign in", (await front(dev.publishableKey, "sign_in", { email, password: "a long enough password" })).status >= 400);
check("list marks them suspended", (await D.listUsers(alice, dev.id)).find((u) => u.id === uid)?.banned === true);
await D.banUser(alice, dev.id, uid, false);
check("restored user can sign in again", (await front(dev.publishableKey, "sign_in", { email, password: "a long enough password" })).body.status === "complete");
check("can't act on another instance's user via my instance ID", (await status(() => D.removeUser(alice, dev.id, "user_notmine"))) === 404);
await D.removeUser(alice, dev.id, uid);
check("deleted user is gone", !(await D.listUsers(alice, dev.id)).some((u) => u.id === uid));

// ---------- Delete instance ----------
check("delete needs the exact name", (await status(() => D.deleteInstance(alice, dev.id, "wrong"))) === 400);
await D.deleteInstance(alice, dev.id, "Acme (dev)");
check("deleted instance's secret key is dead immediately", (await backend(dev.secretKey)) === 401);
check("deleted instance's publishable key is dead", (await fetch(`${AUTH}/v1/client/environment?pk=${dev.publishableKey}`)).status === 401);
check("instance no longer listed", (await D.listInstances(alice)).every((i) => i.id !== dev.id));

await closeDb();
await closeCache();
console.log(failures ? `\n${failures} check(s) failed` : "\nAll dashboard checks passed");
process.exit(failures ? 1 : 0);
