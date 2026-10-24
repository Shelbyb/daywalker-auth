import { NextResponse } from "next/server";
import { z } from "zod";
import { eq } from "drizzle-orm";
import { db, schema } from "@/lib/db";
import { record } from "@/lib/audit";
import { handler } from "@/lib/http";
import { instanceFromSecretKey, invalidateInstance } from "@/lib/auth/instance";
import { deletionSettings, MAX_GRACE_DAYS } from "@/lib/auth/account-deletion";

const input = z.object({ enabled: z.boolean().optional(), graceDays: z.number().int().min(0).max(MAX_GRACE_DAYS).optional() }).strict();

/** Backend API: whether users may delete their own account, and how long they have to change their mind. */
export const GET = handler(async (req: Request) => NextResponse.json(deletionSettings(await instanceFromSecretKey(req))));

export const PATCH = handler(async (req: Request) => {
  const cached = await instanceFromSecretKey(req);
  const p = input.parse(await req.json());
  const [inst] = await db().select().from(schema.instances).where(eq(schema.instances.id, cached.id));
  const accountDeletion = { ...inst.settings.accountDeletion, ...p };
  await db().update(schema.instances).set({ settings: { ...inst.settings, accountDeletion }, updatedAt: new Date() }).where(eq(schema.instances.id, inst.id));
  await invalidateInstance(inst.id);
  const view = deletionSettings({ settings: { ...inst.settings, accountDeletion } });
  void record(inst.id, "instance.settings_updated", { actor: { type: "api" }, data: { accountDeletion: view } });
  return NextResponse.json(view);
});
