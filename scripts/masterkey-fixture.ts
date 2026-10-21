/** Helper for masterkey-e2e.ts. `populate` writes data under the current keys; `verify` reads it back. */
import { sql } from "drizzle-orm";
import { db, schema, closeDb } from "../src/lib/db";
import { closeCache } from "../src/lib/cache";
import { decrypt, encrypt, blindIndex } from "../src/lib/crypto";
import { ENCRYPTED_FIELDS } from "../src/lib/crypto-fields";
import { newId } from "../src/lib/ids";
import { getInstance } from "../src/lib/auth/instance";
import { signUp, signIn, getUser } from "../src/lib/auth/users";
import { createSession } from "../src/lib/auth/sessions";
import { mintSessionToken } from "../src/lib/auth/keys";
import { setProviderConfig } from "../src/lib/auth/oauth";
import { createOrg, invite, listInvitations } from "../src/lib/auth/orgs";
import { startTotpEnrollment } from "../src/lib/auth/mfa";
import { createEndpoint, listEndpoints } from "../src/lib/webhooks";
import { seedInstance } from "./seed";

const mode = process.argv[2];
const email = "ada@example.com", password = "a long enough password";
const out = (o: unknown) => console.log("RESULT " + JSON.stringify(o));

if (mode === "populate") {
  const seed = await seedInstance("Rotation fixture", []);
  const inst = (await getInstance(seed.instanceId))!;
  const userId = await signUp(inst, { email, password, firstName: "Ada", lastName: "Lovelace" });
  await db().update(schema.users).set({ privateMetadataEnc: encrypt(JSON.stringify({ plan: "pro" }), `users.private_metadata:${userId}`) }).where(sql`id = ${userId}`);
  await createSession(inst, userId, { userAgent: "Mozilla/5.0 (X11) Fixture", ip: "203.0.113.9" });
  await setProviderConfig(inst.id, "github", { clientId: "gh-client", clientSecret: "super-secret-value", enabled: true });
  const hook = await createEndpoint(inst.id, { url: "https://93.184.216.34/hook-token-abc" });
  const wd = newId("wd");
  await db().insert(schema.webhookDeliveries).values({ id: wd, instanceId: inst.id, endpointId: hook.id, eventId: newId("evt"), eventType: "user.created", payloadEnc: encrypt(JSON.stringify({ hello: "world" }), `webhook_deliveries.payload:${wd}`), status: "succeeded" });
  const org = await createOrg(inst, userId, "Acme");
  await invite(inst, org.id, userId, "bob@example.com", "member");
  await startTotpEnrollment(inst, userId, email);
  const oa = newId("oa");
  await db().insert(schema.oauthAccounts).values({ id: oa, instanceId: inst.id, userId, provider: "github", providerUserIndex: blindIndex("gh-42", `oauth:${inst.id}:github`), emailEnc: encrypt(email, `oauth_accounts.email:${oa}`) });
  out({ instanceId: inst.id, userId, orgId: org.id, hookUrl: "https://93.184.216.34/hook-token-abc", providerUserIndex: blindIndex("gh-42", `oauth:${inst.id}:github`) });
} else if (mode === "verify") {
  const [{ id: instanceId }] = (await db().execute(sql`select id from instances where name = 'Rotation fixture'`)) as unknown as { id: string }[];
  const inst = (await getInstance(instanceId))!;
  const checks: Record<string, boolean> = {};
  const u0 = (await db().execute(sql`select id from users where instance_id = ${instanceId} limit 1`)) as unknown as { id: string }[];
  const userId = u0[0].id;
  const user = await getUser(instanceId, userId, { includePrivate: true });
  checks.names = user?.firstName === "Ada" && user?.lastName === "Lovelace";
  checks.email = user?.emailAddresses[0]?.email === email;
  checks.privateMetadata = (user as { privateMetadata?: { plan?: string } })?.privateMetadata?.plan === "pro";
  checks.signInByEmailIndex = (await signIn(inst, { email, password })) === userId; // blind index lookup + password
  checks.webhookUrl = (await listEndpoints(instanceId))[0]?.url === "https://93.184.216.34/hook-token-abc";
  const org = (await db().execute(sql`select id from organizations where instance_id = ${instanceId} limit 1`)) as unknown as { id: string }[];
  checks.invitationEmail = (await listInvitations(instanceId, org[0].id, userId))[0]?.email === "bob@example.com";
  checks.signsTokens = typeof (await mintSessionToken(instanceId, { sub: userId, sid: "sess_x" }, 60)) === "string"; // decrypts the signing key
  const oa = (await db().execute(sql`select provider_user_index from oauth_accounts where instance_id = ${instanceId}`)) as unknown as { provider_user_index: string }[];
  checks.oauthIdentityIndexStable = oa[0]?.provider_user_index === blindIndex("gh-42", `oauth:${instanceId}:github`);

  // Every registered column that has data must decrypt under the keys in this process's environment.
  const counts: Record<string, number> = {};
  let allDecrypt = true;
  for (const f of ENCRYPTED_FIELDS) {
    const rows = (await db().execute(sql`select ${sql.join(f.key.map((k) => sql.identifier(k)), sql`, `)}, ${sql.identifier(f.column)} as v from ${sql.identifier(f.table)} where ${sql.identifier(f.column)} is not null`)) as unknown as Record<string, string>[];
    counts[`${f.table}.${f.column}`] = rows.length;
    try {
      for (const r of rows) decrypt(r.v, f.context(r));
    } catch {
      allDecrypt = false;
    }
  }
  checks.everyFieldDecrypts = allDecrypt;
  out({ checks, counts });
}
await closeDb();
await closeCache();
