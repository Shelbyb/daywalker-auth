import { NextResponse } from "next/server";
import { eq } from "drizzle-orm";
import { db, schema } from "@/lib/db";
import { record } from "@/lib/audit";
import { handler } from "@/lib/http";
import { instanceFromSecretKey, invalidateInstance } from "@/lib/auth/instance";
import { apiKeySettings, settingsInput } from "@/lib/auth/api-keys";

/** Backend API: whether end users and organizations can create their own API keys, and the limits. */
export const GET = handler(async (req: Request) => NextResponse.json(apiKeySettings(await instanceFromSecretKey(req))));

export const PATCH = handler(async (req: Request) => {
  const cached = await instanceFromSecretKey(req);
  const input = settingsInput.parse(await req.json());
  // Read the row, not the cached instance: writing a cached object back would undo other settings changes.
  const [inst] = await db().select().from(schema.instances).where(eq(schema.instances.id, cached.id));
  const next = { ...inst.settings.apiKeys, ...input };
  await db().update(schema.instances).set({ settings: { ...inst.settings, apiKeys: next }, updatedAt: new Date() }).where(eq(schema.instances.id, inst.id));
  await invalidateInstance(inst.id);
  void record(inst.id, "instance.settings_updated", { actor: { type: "api" }, data: { apiKeys: next } });
  return NextResponse.json(apiKeySettings({ settings: { ...inst.settings, apiKeys: next } }));
});
