import { eq } from "drizzle-orm";
import { db, schema } from "./db";

export type PlatformRole = (typeof schema.platformRoleEnum.enumValues)[number];

/**
 * The platform role of a dashboard user, or null. Read from Postgres on every call (no cache) so
 * removing someone from the staff takes effect on their very next request.
 */
export async function platformRole(userId: string): Promise<PlatformRole | null> {
  const [row] = await db().select({ role: schema.platformStaff.role }).from(schema.platformStaff).where(eq(schema.platformStaff.userId, userId));
  return row?.role ?? null;
}
