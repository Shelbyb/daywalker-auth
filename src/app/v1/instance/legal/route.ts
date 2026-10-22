import { NextResponse } from "next/server";
import { record } from "@/lib/audit";
import { eq } from "drizzle-orm";
import { handler } from "@/lib/http";
import { instanceFromSecretKey, invalidateInstance } from "@/lib/auth/instance";
import { db, schema } from "@/lib/db";
import { legalInput } from "@/lib/auth/legal";

/** Backend API: set the terms new users must accept. Bump `version` when the terms change. */
export const PUT = handler(async (req: Request) => {
  const inst = await instanceFromSecretKey(req);
  const legal = legalInput.parse(await req.json());
  await db().update(schema.instances).set({ legal, updatedAt: new Date() }).where(eq(schema.instances.id, inst.id));
  await invalidateInstance(inst.id);
  void record(inst.id, "instance.terms_updated", { actor: { type: "api" } });
  return NextResponse.json(legal);
});
