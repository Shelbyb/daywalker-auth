import { NextResponse } from "next/server";
import { and, eq } from "drizzle-orm";
import { handler, errors } from "@/lib/http";
import { instanceFromSecretKey } from "@/lib/auth/instance";
import { getUser } from "@/lib/auth/users";
import { db, schema } from "@/lib/db";
import { cache } from "@/lib/cache";

type Ctx = { params: Promise<{ userId: string }> };

export const GET = handler(async (req: Request, { params }: Ctx) => {
  const inst = await instanceFromSecretKey(req);
  const user = await getUser(inst.id, (await params).userId, { includePrivate: true });
  if (!user) throw errors.notFound("User not found");
  return NextResponse.json(user);
});

/** Delete a user. Cascades to emails, password and sessions; purges their cached sessions. */
export const DELETE = handler(async (req: Request, { params }: Ctx) => {
  const inst = await instanceFromSecretKey(req);
  const { userId } = await params;
  const sess = await db()
    .select({ h: schema.sessions.refreshTokenHash })
    .from(schema.sessions)
    .where(and(eq(schema.sessions.userId, userId), eq(schema.sessions.instanceId, inst.id)));
  const [deleted] = await db()
    .delete(schema.users)
    .where(and(eq(schema.users.id, userId), eq(schema.users.instanceId, inst.id)))
    .returning({ id: schema.users.id });
  if (!deleted) throw errors.notFound("User not found");
  if (sess.length) await cache().del(...sess.map((s) => `sess:${s.h}`));
  return NextResponse.json({ id: userId, deleted: true });
});
