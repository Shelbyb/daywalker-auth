import { sql } from "drizzle-orm";
import { db } from "@/lib/db";
import { cache } from "@/lib/cache";

export const dynamic = "force-dynamic";

const headers = { "Cache-Control": "no-store" };

/** Liveness by default; ?deep=1 also checks Postgres and Valkey. Failures never leak details. */
export async function GET(req: Request) {
  if (new URL(req.url).searchParams.get("deep") !== "1") return Response.json({ ok: true }, { headers });
  try {
    await Promise.all([
      db().execute(sql`select 1`),
      cache().ping().then((r) => {
        if (r !== "PONG") throw new Error("ping");
      }),
    ]);
    return Response.json({ ok: true }, { headers });
  } catch {
    return Response.json({ ok: false }, { status: 503, headers });
  }
}
