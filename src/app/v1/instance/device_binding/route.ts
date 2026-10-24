import { NextResponse } from "next/server";
import { z } from "zod";
import { eq } from "drizzle-orm";
import { db, schema } from "@/lib/db";
import { record } from "@/lib/audit";
import { handler } from "@/lib/http";
import { instanceFromSecretKey, invalidateInstance } from "@/lib/auth/instance";
import { DEVICE_BINDING_MODES } from "@/lib/auth/dpop";
import { sessionSettings } from "@/lib/session-settings";

const input = z.object({ mode: z.enum(DEVICE_BINDING_MODES) }).strict();

/** Backend API: whether sessions are bound to a device key (DPoP): off, optional or required. */
export const GET = handler(async (req: Request) => NextResponse.json({ mode: sessionSettings(await instanceFromSecretKey(req)).deviceBinding }));

export const PATCH = handler(async (req: Request) => {
  const cached = await instanceFromSecretKey(req);
  const { mode } = input.parse(await req.json());
  // Read the row, not the cached instance: writing a cached object back would undo other settings changes.
  const [inst] = await db().select().from(schema.instances).where(eq(schema.instances.id, cached.id));
  const sessions = { ...inst.settings.sessions, deviceBinding: mode };
  await db().update(schema.instances).set({ settings: { ...inst.settings, sessions }, updatedAt: new Date() }).where(eq(schema.instances.id, inst.id));
  await invalidateInstance(inst.id);
  void record(inst.id, "instance.sessions_updated", { actor: { type: "api" }, data: { deviceBinding: mode } });
  return NextResponse.json({ mode });
});
