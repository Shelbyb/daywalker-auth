/**
 * One-time setup for the developer dashboard. Creates the "platform" instance that developers
 * sign in to, then prints the publishable key to put in PLATFORM_PUBLISHABLE_KEY.
 * Run it against your production database after the first deploy:  npm run bootstrap:platform
 */
import { db, schema, closeDb } from "../src/lib/db";
import { closeCache } from "../src/lib/cache";
import { env } from "../src/lib/env";
import { newId } from "../src/lib/ids";
import { createSigningKey } from "../src/lib/auth/keys";
import { publishableKey } from "../src/lib/auth/instance";

const appOrigin = new URL(env().APP_URL).origin;
const accountId = newId("acct");
const instanceId = newId("ins");
await db().insert(schema.accounts).values({ id: accountId, name: "Platform" });
const [inst] = await db()
  .insert(schema.instances)
  .values({
    id: instanceId,
    accountId,
    name: "Daywalker Dashboard",
    environment: appOrigin.startsWith("https://") ? "production" : "development",
    allowedOrigins: [appOrigin], // the dashboard lives on this service's own origin
  })
  .returning();
await createSigningKey(instanceId);

console.log("Platform instance created.\n");
console.log(`PLATFORM_PUBLISHABLE_KEY=${publishableKey(inst)}\n`);
console.log("Add that line to your environment and redeploy. Then open /dashboard and create your account.");
console.log("Run this only once: a second run creates a second, separate platform instance.");
await closeDb();
await closeCache();
