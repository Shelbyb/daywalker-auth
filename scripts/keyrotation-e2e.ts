/** Signing-key rotation: nobody is signed out, old tokens keep verifying, retired keys are purged later. */
import { sql } from "drizzle-orm";
import { decodeProtectedHeader } from "jose";
import { seedInstance } from "./seed";
import { db, closeDb } from "../src/lib/db";
import { cache, closeCache } from "../src/lib/cache";
import { purgeRetiredKeys } from "../src/lib/auth/keys";
import { ApiError } from "../src/lib/http";
import { verifyToken } from "../packages/sdk/src/server";

const AUTH = "http://localhost:3000";
let failures = 0;
const check = (name: string, ok: boolean, detail?: unknown) => {
  console.log(`${ok ? "✓" : "✗"} ${name}${ok ? "" : ` — ${JSON.stringify(detail)}`}`);
  if (!ok) failures++;
};
const { instanceId, publishableKey: pk, secretKey: sk } = await seedInstance("Key rotation E2E", []);
const other = await seedInstance("Key rotation E2E (other)", []);
const cfg = { publishableKey: pk, frontendApi: AUTH };
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const rows = async (q: ReturnType<typeof sql>) => (await db().execute(q)) as unknown as Record<string, any>[];
const bearer = (key: string) => ({ authorization: `Bearer ${key}` });
const front = (path: string, body: unknown) =>
  fetch(`${AUTH}/v1/client/${path}`, { method: "POST", headers: { "content-type": "application/json", "x-publishable-key": pk, origin: AUTH, "x-forwarded-for": `198.51.100.${Math.floor(Math.random() * 250) + 1}` }, body: JSON.stringify(body) }).then((r) => r.json());
const jwks = async () => (await (await fetch(`${AUTH}/i/${instanceId}/.well-known/jwks.json`)).json()).keys as { kid: string }[];

const email = `rot.${Date.now()}@example.com`;
const su = await front("sign_up", { email, password: "a long enough password" });
const kid1 = decodeProtectedHeader(su.jwt).kid!;
check("token is signed by the first key", (await jwks()).some((k) => k.kid === kid1));

check("rotation needs a secret key", (await fetch(`${AUTH}/v1/instance/signing_keys/rotate`, { method: "POST", headers: bearer(pk) })).status === 401);
const rot = await fetch(`${AUTH}/v1/instance/signing_keys/rotate`, { method: "POST", headers: bearer(sk) });
const rb = await rot.json();
check("rotate → 201 with a new key ID", rot.status === 201 && rb.kid && rb.kid !== kid1 && rb.retired === 1, rb);

const keys = (await jwks()).map((k) => k.kid);
check("JWKS publishes both the new and the retired key", keys.includes(kid1) && keys.includes(rb.kid), keys);
check("a token issued before rotation still verifies", (await verifyToken(su.jwt, cfg))?.userId === su.user.id);

const si = await front("sign_in", { email, password: "a long enough password" });
check("tokens issued after rotation use the new key", decodeProtectedHeader(si.jwt).kid === rb.kid);
check("and verify against the published keys", (await verifyToken(si.jwt, cfg))?.userId === su.user.id);

const list = await (await fetch(`${AUTH}/v1/instance/signing_keys`, { headers: bearer(sk) })).json();
check("listing shows one active key and one retired key", list.data.filter((k: { active: boolean }) => k.active).length === 1 && list.data.length === 2, list);
check("listing never exposes private key material", !/private|"d"|privateKey/i.test(JSON.stringify(list)));
const stored = await rows(sql`select private_key_enc from signing_keys where id = ${rb.kid}`);
check("private key is encrypted at rest", String(stored[0].private_key_enc).startsWith("v1."));

// Purge: only retired keys past the grace period; never an active key.
await purgeRetiredKeys(); // clear keys other test instances left behind long ago; the purge is global
check("a freshly retired key is not purged", (await purgeRetiredKeys()) === 0 && (await jwks()).length === 2);
await db().execute(sql`update signing_keys set retired_at = now() - interval '25 hours' where id = ${kid1}`);
await cache().del(`jwks:${instanceId}`);
check("a key retired over a day ago is purged", (await purgeRetiredKeys()) >= 1);
const after = (await jwks()).map((k) => k.kid);
check("JWKS keeps only the active key", after.length === 1 && after[0] === rb.kid, after);
check("current tokens still verify", (await verifyToken((await front("sign_in", { email, password: "a long enough password" })).jwt, cfg)) !== null);

// Limits and isolation
let last = 201;
for (let i = 0; i < 6; i++) last = (await fetch(`${AUTH}/v1/instance/signing_keys/rotate`, { method: "POST", headers: bearer(sk) })).status;
check("rotation is rate limited", last === 429, last);
const otherKeys = await (await fetch(`${AUTH}/v1/instance/signing_keys`, { headers: bearer(other.secretKey) })).json();
check("another instance's keys are untouched", otherKeys.data.length === 1);

// Dashboard path: only the owner can rotate.
const D = await import("../src/lib/dashboard");
const owner = `user_owner${Date.now()}`, stranger = `user_stranger${Date.now()}`;
const mine = await D.createInstance(owner, { name: "Rotate me", environment: "development" });
const status = (fn: () => Promise<unknown>) => fn().then(() => 0, (e) => (e instanceof ApiError ? e.status : -1));
check("another developer can't rotate or list my keys", (await status(() => D.rotateKeys(stranger, mine.id))) === 404 && (await status(() => D.signingKeysFor(stranger, mine.id))) === 404);
await D.rotateKeys(owner, mine.id);
check("owner can rotate from the dashboard", (await D.signingKeysFor(owner, mine.id)).length === 2);

await closeDb();
await closeCache();
console.log(failures ? `\n${failures} check(s) failed` : "\nAll key rotation checks passed");
process.exit(failures ? 1 : 0);
