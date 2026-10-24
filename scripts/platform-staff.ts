/**
 * Grants (or removes) platform staff access for a dashboard user. Use it once to make the first
 * platform admin; after that, admins manage the staff in /dashboard/platform/staff.
 *
 *   npm run platform:staff -- you@example.com admin     # or "user"
 *   npm run platform:staff -- you@example.com remove
 *
 * The person must have signed in to /dashboard once (so they exist in the platform instance).
 * Needs PLATFORM_PUBLISHABLE_KEY and MASTER_KEY (emails are found through the blind index).
 */
import { and, eq } from "drizzle-orm";
import { db, schema, closeDb } from "../src/lib/db";
import { closeCache } from "../src/lib/cache";
import { blindIndex } from "../src/lib/crypto";
import { parsePublishableKey } from "../src/lib/auth/instance";
import { recordPlatform } from "../src/lib/platform-audit";

const [rawEmail, action = "admin"] = process.argv.slice(2);
const pid = parsePublishableKey(process.env.PLATFORM_PUBLISHABLE_KEY);
if (!rawEmail || !["admin", "user", "remove"].includes(action) || !pid) {
  console.error("Usage: npm run platform:staff -- <email> <admin|user|remove>   (PLATFORM_PUBLISHABLE_KEY must be set)");
  process.exit(1);
}
const email = rawEmail.trim().toLowerCase();
const [hit] = await db()
  .select({ userId: schema.emailAddresses.userId })
  .from(schema.emailAddresses)
  .where(and(eq(schema.emailAddresses.instanceId, pid), eq(schema.emailAddresses.emailIndex, blindIndex(email, `email:${pid}`))));
if (!hit) {
  console.error(`No dashboard user with email ${email}. Sign in to /dashboard once first.`);
  process.exit(1);
}
if (action === "remove") {
  await db().delete(schema.platformStaff).where(eq(schema.platformStaff.userId, hit.userId));
  await recordPlatform("staff.removed", { actorId: "cli", target: hit.userId, data: { email, via: "cli" } });
  console.log(`${email} is no longer platform staff.`);
} else {
  const role = action as "admin" | "user";
  await db().insert(schema.platformStaff).values({ userId: hit.userId, role, createdBy: "cli" }).onConflictDoUpdate({ target: schema.platformStaff.userId, set: { role } });
  await recordPlatform("staff.added", { actorId: "cli", target: hit.userId, data: { email, role, via: "cli" } });
  console.log(`${email} is now platform ${role}. Open /dashboard/platform.`);
}
await closeDb();
await closeCache();
