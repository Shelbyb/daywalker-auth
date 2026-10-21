import { NextResponse } from "next/server";
import { desc, eq } from "drizzle-orm";
import { z } from "zod";
import { handler } from "@/lib/http";
import { instanceFromSecretKey } from "@/lib/auth/instance";
import { db, schema } from "@/lib/db";
import { getUser } from "@/lib/auth/users";

/** Backend API (secret key): list users. Never callable from browsers (no CORS headers). */
export const GET = handler(async (req: Request) => {
  const inst = await instanceFromSecretKey(req);
  const q = z
    .object({ limit: z.coerce.number().int().min(1).max(100).default(20), offset: z.coerce.number().int().min(0).default(0) })
    .parse(Object.fromEntries(new URL(req.url).searchParams));
  const rows = await db()
    .select({ id: schema.users.id })
    .from(schema.users)
    .where(eq(schema.users.instanceId, inst.id))
    .orderBy(desc(schema.users.createdAt))
    .limit(q.limit)
    .offset(q.offset);
  const data = await Promise.all(rows.map((r) => getUser(inst.id, r.id, { includePrivate: true })));
  return NextResponse.json({ data });
});
