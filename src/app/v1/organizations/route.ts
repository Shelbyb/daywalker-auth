import { NextResponse } from "next/server";
import { desc, eq } from "drizzle-orm";
import { z } from "zod";
import { handler } from "@/lib/http";
import { instanceFromSecretKey } from "@/lib/auth/instance";
import { db, schema } from "@/lib/db";

/** Backend API: list organizations in this instance. */
export const GET = handler(async (req: Request) => {
  const inst = await instanceFromSecretKey(req);
  const q = z
    .object({ limit: z.coerce.number().int().min(1).max(100).default(20), offset: z.coerce.number().int().min(0).default(0) })
    .parse(Object.fromEntries(new URL(req.url).searchParams));
  const data = await db()
    .select({ id: schema.organizations.id, name: schema.organizations.name, slug: schema.organizations.slug, createdAt: schema.organizations.createdAt })
    .from(schema.organizations)
    .where(eq(schema.organizations.instanceId, inst.id))
    .orderBy(desc(schema.organizations.createdAt))
    .limit(q.limit)
    .offset(q.offset);
  return NextResponse.json({ data });
});
