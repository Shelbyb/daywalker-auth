import { sql } from "drizzle-orm";
import { db, closeDb } from "../../src/lib/db";
import { cache, closeCache } from "../../src/lib/cache";
import { blindIndex } from "../../src/lib/crypto";
import { parsePublishableKey, invalidateInstance } from "../../src/lib/auth/instance";
const [cmd, arg] = process.argv.slice(2);
if (cmd === "enable") {
  const id = parsePublishableKey(process.env.NEXT_PUBLIC_DAYWALKER_PUBLISHABLE_KEY)!;
  await db().execute(sql`update instances set settings = settings || '{"emailCodeSignIn":true}'::jsonb where id = ${id}`);
  await invalidateInstance(id);
  console.log("ok");
} else if (cmd === "enable-passkey-signup") {
  const id = parsePublishableKey(arg)!;
  await db().execute(sql`update instances set settings = settings || '{"passkeySignUp":true}'::jsonb where id = ${id}`);
  await invalidateInstance(id);
  console.log("ok");
} else if (cmd === "mail") {
  const t = await cache().get(`devmail:${blindIndex(arg, "devmail")}`);
  console.log("CODE=" + (t?.match(/\b(\d{6})\b/)?.[1] ?? ""));
  await cache().del(`devmail:${blindIndex(arg, "devmail")}`);
}
await closeDb(); await closeCache();
