import { NextResponse } from "next/server";
import { eq } from "drizzle-orm";
import { z } from "zod";
import { handler } from "@/lib/http";
import { instanceFromSecretKey, invalidateInstance } from "@/lib/auth/instance";
import { db, schema } from "@/lib/db";

const httpsOrLocal = z.string().url().max(2048).refine((u) => /^https:\/\//.test(u) || /^http:\/\/localhost[:/]/.test(u), "must be https");

const body = z.object({
  required: z.boolean(),
  termsUrl: httpsOrLocal.nullable(),
  privacyUrl: httpsOrLocal.nullable(),
  version: z.string().trim().min(1).max(40),
}).refine((b) => !b.required || b.termsUrl, { message: "termsUrl is required when acceptance is required", path: ["termsUrl"] });

/** Backend API: set the terms new users must accept. Bump `version` when the terms change. */
export const PUT = handler(async (req: Request) => {
  const inst = await instanceFromSecretKey(req);
  const legal = body.parse(await req.json());
  await db().update(schema.instances).set({ legal, updatedAt: new Date() }).where(eq(schema.instances.id, inst.id));
  await invalidateInstance(inst.id);
  return NextResponse.json(legal);
});
