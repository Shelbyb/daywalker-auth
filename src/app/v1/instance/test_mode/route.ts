import { NextResponse } from "next/server";
import { eq } from "drizzle-orm";
import { z } from "zod";
import { db, schema } from "@/lib/db";
import { record } from "@/lib/audit";
import { handler } from "@/lib/http";
import { instanceFromSecretKey, invalidateInstance } from "@/lib/auth/instance";
import { assertCanEnableTestMode, testModeView } from "@/lib/auth/test-mode";

/** Backend API: test mode (fixed code 424242 for +daywalker_test addresses and reserved phone numbers). Development instances only. */
export const GET = handler(async (req: Request) => NextResponse.json(testModeView(await instanceFromSecretKey(req))));

export const PATCH = handler(async (req: Request) => {
  const cached = await instanceFromSecretKey(req);
  const { enabled } = z.object({ enabled: z.boolean() }).strict().parse(await req.json());
  if (enabled) assertCanEnableTestMode(cached); // turning it off is always allowed
  // Read the row, not the cached instance: writing a cached object back would undo other settings changes.
  const [inst] = await db().select().from(schema.instances).where(eq(schema.instances.id, cached.id));
  await db().update(schema.instances).set({ settings: { ...inst.settings, testMode: { enabled } }, updatedAt: new Date() }).where(eq(schema.instances.id, inst.id));
  await invalidateInstance(inst.id);
  void record(inst.id, "instance.test_mode_updated", { actor: { type: "api" }, data: { enabled } });
  return NextResponse.json(testModeView({ ...inst, settings: { ...inst.settings, testMode: { enabled } } }));
});
