/**
 * Creates a developer account, an instance, its first signing key and a secret key.
 * The secret key is printed once and only its SHA-256 is stored.
 */
import { db, schema, closeDb } from "../src/lib/db";
import { closeCache } from "../src/lib/cache";
import { newId, newToken, sha256 } from "../src/lib/ids";
import { createSigningKey } from "../src/lib/auth/keys";
import { publishableKey } from "../src/lib/auth/instance";

export async function seedInstance(name = "My App", allowedOrigins: string[] = []) {
  const accountId = newId("acct");
  const instanceId = newId("ins");
  const applicationId = newId("app");
  await db().insert(schema.accounts).values({ id: accountId, name: "Default" });
  await db().insert(schema.applications).values({ id: applicationId, accountId, name });
  const [inst] = await db().insert(schema.instances).values({ id: instanceId, accountId, name, allowedOrigins, applicationId }).returning();
  await createSigningKey(instanceId);
  const secret = `sk_test_${newToken(32)}`;
  await db().insert(schema.apiKeys).values({
    id: newId("sk"),
    instanceId,
    name: "Default",
    keyHash: sha256(secret),
    keyPrefix: secret.slice(0, 12),
  });
  return { instanceId, accountId, applicationId, publishableKey: publishableKey(inst), secretKey: secret };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const origins = process.argv.slice(2);
  const r = await seedInstance("My App", origins);
  console.log(`Instance:        ${r.instanceId}`);
  console.log(`Publishable key: ${r.publishableKey}`);
  console.log(`Secret key:      ${r.secretKey}   (shown once; store it in your secrets manager)`);
  await closeDb();
  await closeCache();
}
