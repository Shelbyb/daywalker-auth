import { NextResponse } from "next/server";
import { z } from "zod";
import { handler } from "@/lib/http";
import { instanceFromSecretKey } from "@/lib/auth/instance";
import { roleKey } from "@/lib/auth/org-roles";
import { setMemberRole } from "@/lib/auth/orgs";

/** Backend API: set a member's role (built-in or custom). The last admin can't be demoted. */
export const PATCH = handler(async (req: Request, { params }: { params: Promise<{ orgId: string; userId: string }> }) => {
  const inst = await instanceFromSecretKey(req);
  const { orgId, userId } = await params;
  const { role } = z.object({ role: roleKey }).parse(await req.json());
  await setMemberRole(inst.id, orgId, userId, role);
  return NextResponse.json({ userId, role });
});
