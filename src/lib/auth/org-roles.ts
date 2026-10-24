/**
 * Organization roles and permissions. "admin" and "member" are built in; developers can define more per instance.
 * A permission is a string like "org:billing:manage" (two or three lowercase segments). The built-in "admin" holds
 * every system permission plus every custom permission defined in the instance, so it is never locked out of a feature.
 * Rules that stop privilege escalation: you can only assign or change roles that your own role covers.
 */
import { and, eq } from "drizzle-orm";
import { z } from "zod";
import { db, schema } from "../db";
import { cache } from "../cache";
import { errors } from "../http";
import { record, type Actor } from "../audit";
import type { Instance } from "../db/schema";

export const SYSTEM_PERMISSIONS = ["org:read", "org:manage", "members:read", "members:manage", "invitations:manage"] as const;
/** Permissions that let the holder change who else is in the organization or the organization itself. */
export const MANAGE_PERMISSIONS = ["org:manage", "members:manage", "invitations:manage"];
const MEMBER_PERMISSIONS = ["org:read", "members:read"];
export const BUILT_IN = ["admin", "member"] as const;

export const MAX_ROLES = 20;
export const MAX_PERMISSIONS_PER_ROLE = 25;
export const MAX_CUSTOM_PERMISSIONS = 60;

export const permissionString = z.string().trim().toLowerCase().max(48).regex(/^[a-z][a-z0-9_]{0,15}:[a-z][a-z0-9_]{0,15}(:[a-z][a-z0-9_]{0,15})?$/, "Use a form like org:billing:manage");
export const roleKey = z.string().trim().toLowerCase().regex(/^[a-z][a-z0-9_]{1,30}$/, "Use lowercase letters, digits and underscores (2-31 characters)");
export const roleInput = z.object({
  key: roleKey,
  name: z.string().trim().min(1).max(60),
  description: z.string().trim().max(200).nullish(),
  permissions: z.array(permissionString).max(MAX_PERMISSIONS_PER_ROLE),
});
export const roleUpdate = roleInput.omit({ key: true }).partial();

export type RoleDef = { key: string; name: string; description: string | null; permissions: string[]; builtIn: boolean };
const cacheKey = (instanceId: string) => `orgroles:${instanceId}`;
export const forgetRoles = (instanceId: string) => cache().del(cacheKey(instanceId));

async function customRoles(instanceId: string) {
  const hit = await cache().get(cacheKey(instanceId));
  if (hit) return JSON.parse(hit) as { key: string; name: string; description: string | null; permissions: string[] }[];
  const rows = await db()
    .select({ key: schema.orgRoles.key, name: schema.orgRoles.name, description: schema.orgRoles.description, permissions: schema.orgRoles.permissions })
    .from(schema.orgRoles)
    .where(eq(schema.orgRoles.instanceId, instanceId));
  await cache().set(cacheKey(instanceId), JSON.stringify(rows), "EX", 60);
  return rows;
}

/** Every role of the instance, built-ins first. Admin's list includes every custom permission. */
export async function listRoles(instanceId: string): Promise<RoleDef[]> {
  const custom = await customRoles(instanceId);
  const all = [...new Set(custom.flatMap((r) => r.permissions))].sort();
  return [
    { key: "admin", name: "Admin", description: "Full access, including every custom permission", permissions: [...SYSTEM_PERMISSIONS, ...all], builtIn: true },
    { key: "member", name: "Member", description: "Read access", permissions: MEMBER_PERMISSIONS, builtIn: true },
    ...custom.map((r) => ({ ...r, builtIn: false })),
  ];
}

/** Permissions of a role. An unknown role (for example a deleted one) has none. */
export async function permissionsOf(instanceId: string, role: string): Promise<string[]> {
  return (await listRoles(instanceId)).find((r) => r.key === role)?.permissions ?? [];
}

export async function assertRoleExists(instanceId: string, role: string) {
  if (!(await listRoles(instanceId)).some((r) => r.key === role)) throw errors.badRequest("unknown_role", `There is no role "${role}"`);
}

/** Does `actorRole` cover everything `target` can do? Admin covers all. */
export async function covers(instanceId: string, actorRole: string, targetRole: string) {
  if (actorRole === "admin") return true;
  if (targetRole === "admin") return false;
  const [mine, theirs] = await Promise.all([permissionsOf(instanceId, actorRole), permissionsOf(instanceId, targetRole)]);
  return theirs.every((p) => mine.includes(p));
}

/** Throws unless the actor's role covers the role being granted. */
export async function assertCanGrant(instanceId: string, actorRole: string, targetRole: string) {
  if (!(await covers(instanceId, actorRole, targetRole))) throw errors.forbidden("You can't give someone a role with more access than yours").withCode("role_exceeds_yours");
}

/** Roles that may be given to people joining through a verified domain: never one that can manage the organization. */
export async function assertSafeForAutoJoin(instanceId: string, role: string) {
  await assertRoleExists(instanceId, role);
  const perms = await permissionsOf(instanceId, role);
  if (role === "admin" || perms.some((p) => MANAGE_PERMISSIONS.includes(p)))
    throw errors.badRequest("role_not_allowed", "People who join by email domain can't get a role that manages the organization");
}

function checkPermissionBudget(existing: { key: string; permissions: string[] }[], key: string, permissions: string[]) {
  const set = new Set(existing.filter((r) => r.key !== key).flatMap((r) => r.permissions));
  for (const p of permissions) if (!(SYSTEM_PERMISSIONS as readonly string[]).includes(p)) set.add(p);
  const custom = [...set].filter((p) => !(SYSTEM_PERMISSIONS as readonly string[]).includes(p));
  if (custom.length > MAX_CUSTOM_PERMISSIONS)
    throw errors.limitReached(`An instance can define at most ${MAX_CUSTOM_PERMISSIONS} different custom permissions (they travel in the token)`);
}

export async function createRole(inst: Instance, input: z.infer<typeof roleInput>, actor?: Actor) {
  if ((BUILT_IN as readonly string[]).includes(input.key)) throw errors.conflict("role_exists", `"${input.key}" is a built-in role`);
  const existing = await customRoles(inst.id);
  if (existing.length >= MAX_ROLES) throw errors.limitReached(`An instance can have at most ${MAX_ROLES} custom roles`);
  if (existing.some((r) => r.key === input.key)) throw errors.conflict("role_exists", "A role with that key already exists");
  const permissions = [...new Set(input.permissions)];
  checkPermissionBudget(existing, input.key, permissions);
  await db().insert(schema.orgRoles).values({ instanceId: inst.id, key: input.key, name: input.name, description: input.description ?? null, permissions });
  await forgetRoles(inst.id);
  void record(inst.id, "org_role.created", { actor, target: input.key, data: { permissions } });
  return (await listRoles(inst.id)).find((r) => r.key === input.key)!;
}

export async function updateRole(inst: Instance, key: string, input: z.infer<typeof roleUpdate>, actor?: Actor) {
  const existing = await customRoles(inst.id);
  const cur = existing.find((r) => r.key === key);
  if (!cur) throw errors.notFound("Role not found");
  const permissions = input.permissions ? [...new Set(input.permissions)] : cur.permissions;
  checkPermissionBudget(existing, key, permissions);
  // A role used for domain joins must not gain a managing permission.
  if (permissions.some((p) => MANAGE_PERMISSIONS.includes(p))) {
    const [d] = await db().select({ id: schema.orgDomains.id }).from(schema.orgDomains).where(and(eq(schema.orgDomains.instanceId, inst.id), eq(schema.orgDomains.role, key)));
    if (d) throw errors.conflict("role_in_use", "This role is used for people who join by email domain, which can't manage the organization");
  }
  await db()
    .update(schema.orgRoles)
    .set({ name: input.name ?? cur.name, description: input.description === undefined ? cur.description : input.description, permissions, updatedAt: new Date() })
    .where(and(eq(schema.orgRoles.instanceId, inst.id), eq(schema.orgRoles.key, key)));
  await forgetRoles(inst.id);
  void record(inst.id, "org_role.updated", { actor, target: key, data: { permissions } });
  return (await listRoles(inst.id)).find((r) => r.key === key)!;
}

export async function deleteRole(inst: Instance, key: string, actor?: Actor) {
  if (!(await customRoles(inst.id)).some((r) => r.key === key)) throw errors.notFound("Role not found");
  const [m] = await db()
    .select({ u: schema.memberships.userId })
    .from(schema.memberships)
    .innerJoin(schema.organizations, eq(schema.organizations.id, schema.memberships.orgId))
    .where(and(eq(schema.organizations.instanceId, inst.id), eq(schema.memberships.role, key)))
    .limit(1);
  const [i] = await db()
    .select({ id: schema.invitations.id })
    .from(schema.invitations)
    .innerJoin(schema.organizations, eq(schema.organizations.id, schema.invitations.orgId))
    .where(and(eq(schema.organizations.instanceId, inst.id), eq(schema.invitations.role, key)))
    .limit(1);
  const [d] = await db().select({ id: schema.orgDomains.id }).from(schema.orgDomains).where(and(eq(schema.orgDomains.instanceId, inst.id), eq(schema.orgDomains.role, key))).limit(1);
  const o = inst.settings.organizations;
  if (m || i || d || o?.defaultRole === key || o?.creatorRole === key)
    throw errors.conflict("role_in_use", "This role is still assigned to members, invitations or settings. Move them to another role first");
  await db().delete(schema.orgRoles).where(and(eq(schema.orgRoles.instanceId, inst.id), eq(schema.orgRoles.key, key)));
  await forgetRoles(inst.id);
  void record(inst.id, "org_role.deleted", { actor, target: key });
}
