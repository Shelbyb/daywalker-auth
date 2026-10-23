/**
 * Organization roles driven by SCIM groups. Opt-in per connection: only when the connection has an
 * organization AND a list of admin group names. Members of those groups are admins of the organization;
 * everyone else the connection manages is a member. Two safety rules:
 * - Only people this connection manages are ever changed (never someone it doesn't provision).
 * - The organization's last admin is never demoted, so a bad group push can't lock everyone out.
 *
 * Kept free of other auth imports (SAML sign-in and the SCIM routes both use it).
 */
import { and, eq, inArray, ne, sql } from "drizzle-orm";
import { db, schema } from "../db";
import { record } from "../audit";

export type RoleConn = { id: string; instanceId: string; orgId: string | null; scimAdminGroups: string[] };

/** Group names are compared in lowercase. */
export const normalizeGroupNames = (names: string[]) => [...new Set(names.map((n) => n.trim().toLowerCase()).filter(Boolean))];

/** The role a managed person should have right now, from their group memberships. */
export async function roleFromGroups(conn: RoleConn, userId: string): Promise<"admin" | "member"> {
  if (!conn.scimAdminGroups.length) return "member";
  const rows = await db()
    .select({ n: schema.scimGroups.displayName })
    .from(schema.scimGroupMembers)
    .innerJoin(schema.scimGroups, eq(schema.scimGroups.id, schema.scimGroupMembers.groupId))
    .where(and(eq(schema.scimGroups.connectionId, conn.id), eq(schema.scimGroupMembers.userId, userId)));
  return rows.some((r) => conn.scimAdminGroups.includes(r.n.toLowerCase())) ? "admin" : "member";
}

/** Brings the organization roles of these people in line with their groups. Returns how many changed. */
export async function syncRoles(conn: RoleConn, userIds: string[]) {
  if (!conn.orgId || !conn.scimAdminGroups.length || !userIds.length) return 0;
  const orgId = conn.orgId;
  let changed = 0;
  for (let i = 0; i < userIds.length; i += 200) {
    const managed = await db()
      .select({ u: schema.scimUsers.userId })
      .from(schema.scimUsers)
      .where(and(eq(schema.scimUsers.connectionId, conn.id), inArray(schema.scimUsers.userId, userIds.slice(i, i + 200))));
    for (const { u } of managed) {
      const desired = await roleFromGroups(conn, u);
      const [m] = await db().select({ role: schema.memberships.role }).from(schema.memberships).where(and(eq(schema.memberships.orgId, orgId), eq(schema.memberships.userId, u)));
      if (!m) {
        // Not a member yet: only group admins are added up front (everyone else joins at their first SSO sign-in).
        if (desired !== "admin") continue;
        await db().insert(schema.memberships).values({ orgId, userId: u, role: "admin" }).onConflictDoNothing();
      } else if (m.role === desired) continue;
      else if (desired === "member") {
        const [{ n }] = (await db()
          .select({ n: sql<number>`count(*)::int` })
          .from(schema.memberships)
          .where(and(eq(schema.memberships.orgId, orgId), eq(schema.memberships.role, "admin"), ne(schema.memberships.userId, u)))) as { n: number }[];
        if (n === 0) continue; // never leave an organization without an admin
        await db().update(schema.memberships).set({ role: "member" }).where(and(eq(schema.memberships.orgId, orgId), eq(schema.memberships.userId, u)));
      } else {
        await db().update(schema.memberships).set({ role: "admin" }).where(and(eq(schema.memberships.orgId, orgId), eq(schema.memberships.userId, u)));
      }
      changed++;
      void record(conn.instanceId, "scim_role.changed", { actor: { type: "api", id: conn.id }, target: u, data: { connectionId: conn.id, organizationId: orgId, role: desired } });
    }
  }
  return changed;
}

/** All people this connection manages (used when its admin group list changes). */
export async function managedUserIds(connectionId: string) {
  return (await db().select({ u: schema.scimUsers.userId }).from(schema.scimUsers).where(eq(schema.scimUsers.connectionId, connectionId))).map((r) => r.u);
}
