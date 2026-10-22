import { NextResponse } from "next/server";
import { eq } from "drizzle-orm";
import { z } from "zod";
import { handler } from "@/lib/http";
import { instanceFromSecretKey, invalidateInstance } from "@/lib/auth/instance";
import { db, schema } from "@/lib/db";
import { accentInput } from "@/lib/email-templates";
import { record } from "@/lib/audit";

/** Backend API: the button and link color used in emails. `null` restores the default. */
export const PUT = handler(async (req: Request) => {
  const inst = await instanceFromSecretKey(req);
  const { accentColor } = z.object({ accentColor: accentInput.nullable() }).parse(await req.json());
  await db().update(schema.instances).set({ settings: { ...inst.settings, emailAccentColor: accentColor ?? undefined }, updatedAt: new Date() }).where(eq(schema.instances.id, inst.id));
  await invalidateInstance(inst.id);
  void record(inst.id, "email_template.updated", { actor: { type: "api" }, target: "branding", data: { accentColor } });
  return NextResponse.json({ accentColor });
});
