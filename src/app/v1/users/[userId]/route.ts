import { NextResponse } from "next/server";
import { handler, errors } from "@/lib/http";
import { instanceFromSecretKey } from "@/lib/auth/instance";
import { getUser, deleteUser } from "@/lib/auth/users";

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
  await deleteUser(inst.id, userId);
  return NextResponse.json({ id: userId, deleted: true });
});
