import { NextResponse } from "next/server";
import { handler, errors } from "@/lib/http";
import { getInstance } from "@/lib/auth/instance";
import { getJwks } from "@/lib/auth/keys";

/** Public keys only. Safe to cache briefly and to serve cross-origin. */
export const GET = handler(async (_req: Request, { params }: { params: Promise<{ instanceId: string }> }) => {
  const { instanceId } = await params;
  if (!(await getInstance(instanceId))) throw errors.notFound();
  return NextResponse.json(await getJwks(instanceId), {
    headers: { "cache-control": "public, max-age=300", "access-control-allow-origin": "*" },
  });
});
