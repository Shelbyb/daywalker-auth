import { NextResponse } from "next/server";
import { eq } from "drizzle-orm";
import { handler, errors } from "@/lib/http";
import { instanceFromSecretKey } from "@/lib/auth/instance";
import { getOrg } from "@/lib/auth/orgs";
import { db, schema } from "@/lib/db";

/** Backend API: members of an organization (user IDs and roles). */
export const GET = handler(async (req: Request, { params }: { params: Promise<{ orgId: string }> }) => {
  const inst = await instanceFromSecretKey(req);
  const { orgId } = await params;
  if (!(await getOrg(inst.id, orgId))) throw errors.notFound("Organization not found");
  const data = await db()
    .select({ userId: schema.memberships.userId, role: schema.memberships.role, joinedAt: schema.memberships.createdAt })
    .from(schema.memberships)
    .where(eq(schema.memberships.orgId, orgId));
  return NextResponse.json({ data });
});
