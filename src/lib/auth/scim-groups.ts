/**
 * SCIM 2.0 Groups (RFC 7643 §4.2), one set per SSO connection. Groups only matter for one thing here:
 * when the connection lists admin group names, members of those groups become admins of its
 * organization (see scim-roles.ts). A group can only contain people this connection manages.
 */
import { and, asc, eq, inArray, sql } from "drizzle-orm";
import { z } from "zod";
import { db, schema } from "../db";
import { newId } from "../ids";
import { record } from "../audit";
import { ScimError, SCHEMAS, scimBaseUrl, type ScimCtx } from "./scim";
import { syncRoles, type RoleConn } from "./scim-roles";

const MAX_GROUPS = 500;
const MAX_MEMBERS = 5000;
const MAX_PAGE = 200;
const str = (max: number) => z.string().trim().max(max);
const actor = (c: ScimCtx) => ({ type: "api" as const, id: c.conn.id });
const roleConn = (c: ScimCtx): RoleConn => ({ id: c.conn.id, instanceId: c.inst.id, orgId: c.conn.orgId, scimAdminGroups: c.conn.scimAdminGroups });

type Group = typeof schema.scimGroups.$inferSelect;

async function load(c: ScimCtx, id: string) {
  const [g] = await db().select().from(schema.scimGroups).where(and(eq(schema.scimGroups.id, id), eq(schema.scimGroups.connectionId, c.conn.id)));
  if (!g) throw new ScimError(404, undefined, "Group not found");
  return g;
}

const memberIds = async (groupId: string) =>
  (await db().select({ u: schema.scimGroupMembers.userId }).from(schema.scimGroupMembers).where(eq(schema.scimGroupMembers.groupId, groupId))).map((r) => r.u);

async function toScim(c: ScimCtx, g: Group) {
  const ids = await memberIds(g.id);
  return {
    schemas: [SCHEMAS.group],
    id: g.id,
    ...(g.externalId ? { externalId: g.externalId } : {}),
    displayName: g.displayName,
    members: ids.map((v) => ({ value: v, $ref: `${scimBaseUrl(c.conn.id)}/Users/${v}`, type: "User" })),
    meta: { resourceType: "Group", created: g.createdAt, location: `${scimBaseUrl(c.conn.id)}/Groups/${g.id}` },
  };
}

/** Only people this connection manages may be members. */
async function checkMembers(c: ScimCtx, ids: string[]) {
  const unique = [...new Set(ids)];
  if (unique.length > MAX_MEMBERS) throw new ScimError(400, "invalidValue", `A group can have at most ${MAX_MEMBERS} members`);
  for (let i = 0; i < unique.length; i += 500) {
    const part = unique.slice(i, i + 500);
    const found = await db()
      .select({ u: schema.scimUsers.userId })
      .from(schema.scimUsers)
      .where(and(eq(schema.scimUsers.connectionId, c.conn.id), inArray(schema.scimUsers.userId, part)));
    if (found.length !== part.length) throw new ScimError(400, "invalidValue", "A member isn't a user managed by this connection");
  }
  return unique;
}

async function nameTaken(c: ScimCtx, name: string, exceptId?: string) {
  const rows = await db().select({ id: schema.scimGroups.id }).from(schema.scimGroups).where(and(eq(schema.scimGroups.connectionId, c.conn.id), sql`lower(${schema.scimGroups.displayName}) = lower(${name})`));
  return rows.some((r) => r.id !== exceptId);
}

const valuesOf = (v: unknown): string[] => {
  const list = Array.isArray(v) ? v : v && typeof v === "object" ? [v] : [];
  return list.map((m) => (m as { value?: unknown })?.value).filter((x): x is string => typeof x === "string" && x.length > 0 && x.length <= 100);
};

// ---------- Operations ----------

export async function groupCreate(c: ScimCtx, body: unknown) {
  const b = z.object({ displayName: str(200).min(1), externalId: str(255).nullish(), members: z.array(z.unknown()).max(MAX_MEMBERS).optional() }).passthrough().safeParse(body);
  if (!b.success) throw new ScimError(400, "invalidSyntax", "The request body isn't a valid SCIM Group");
  const [{ n }] = (await db().select({ n: sql<number>`count(*)::int` }).from(schema.scimGroups).where(eq(schema.scimGroups.connectionId, c.conn.id))) as { n: number }[];
  if (n >= MAX_GROUPS) throw new ScimError(400, "invalidValue", `At most ${MAX_GROUPS} groups per connection`);
  if (await nameTaken(c, b.data.displayName)) throw new ScimError(409, "uniqueness", "A group with that displayName already exists");
  const members = await checkMembers(c, valuesOf(b.data.members));
  const id = newId("sg");
  await db().transaction(async (tx) => {
    await tx.insert(schema.scimGroups).values({ id, connectionId: c.conn.id, displayName: b.data.displayName, externalId: b.data.externalId ?? null });
    if (members.length) await tx.insert(schema.scimGroupMembers).values(members.map((userId) => ({ groupId: id, userId })));
  });
  await syncRoles(roleConn(c), members);
  void record(c.inst.id, "scim_group.created", { actor: actor(c), data: { connectionId: c.conn.id, groupId: id, name: b.data.displayName, members: members.length } });
  return toScim(c, await load(c, id));
}

export const groupGet = async (c: ScimCtx, id: string) => toScim(c, await load(c, id));

export async function groupList(c: ScimCtx, q: { filter?: string; startIndex?: number; count?: number }) {
  const start = Math.max(1, Math.floor(q.startIndex ?? 1));
  const count = Math.min(MAX_PAGE, Math.max(0, Math.floor(q.count ?? 100)));
  const respond = (total: number, n: number) => ({ schemas: [SCHEMAS.list], totalResults: total, startIndex: start, itemsPerPage: n });
  if (q.filter) {
    const m = q.filter.match(/^\s*displayName\s+eq\s+"((?:[^"\\]|\\.){0,300})"\s*$/i);
    if (!m) throw new ScimError(400, "invalidFilter", 'Only `displayName eq "..."` is supported for groups');
    const name = m[1].replace(/\\(.)/g, "$1");
    const rows = await db().select().from(schema.scimGroups).where(and(eq(schema.scimGroups.connectionId, c.conn.id), sql`lower(${schema.scimGroups.displayName}) = lower(${name})`));
    return { ...respond(rows.length, rows.length), Resources: await Promise.all(rows.map((g) => toScim(c, g))) };
  }
  const [{ n }] = (await db().select({ n: sql<number>`count(*)::int` }).from(schema.scimGroups).where(eq(schema.scimGroups.connectionId, c.conn.id))) as { n: number }[];
  const rows = count ? await db().select().from(schema.scimGroups).where(eq(schema.scimGroups.connectionId, c.conn.id)).orderBy(asc(schema.scimGroups.createdAt), asc(schema.scimGroups.id)).limit(count).offset(start - 1) : [];
  return { ...respond(n, rows.length), Resources: await Promise.all(rows.map((g) => toScim(c, g))) };
}

type Change = { displayName?: string; externalId?: string | null; members?: Set<string> };

/** Writes the new name/members, then re-syncs the roles of everyone whose membership changed. */
async function save(c: ScimCtx, g: Group, ch: Change) {
  const before = new Set(await memberIds(g.id));
  const after = ch.members ? new Set(await checkMembers(c, [...ch.members])) : before;
  if (ch.displayName !== undefined && ch.displayName !== g.displayName && (await nameTaken(c, ch.displayName, g.id))) throw new ScimError(409, "uniqueness", "A group with that displayName already exists");
  const added = [...after].filter((u) => !before.has(u));
  const removed = [...before].filter((u) => !after.has(u));
  await db().transaction(async (tx) => {
    const set: Partial<Group> = {};
    if (ch.displayName !== undefined) set.displayName = ch.displayName;
    if (ch.externalId !== undefined) set.externalId = ch.externalId;
    if (Object.keys(set).length) await tx.update(schema.scimGroups).set(set).where(eq(schema.scimGroups.id, g.id));
    for (const u of removed) await tx.delete(schema.scimGroupMembers).where(and(eq(schema.scimGroupMembers.groupId, g.id), eq(schema.scimGroupMembers.userId, u)));
    if (added.length) await tx.insert(schema.scimGroupMembers).values(added.map((userId) => ({ groupId: g.id, userId }))).onConflictDoNothing();
  });
  // A rename can move the whole group in or out of the admin list.
  const renamed = ch.displayName !== undefined && ch.displayName !== g.displayName;
  await syncRoles(roleConn(c), renamed ? [...after, ...removed] : [...added, ...removed]);
  void record(c.inst.id, "scim_group.updated", { actor: actor(c), data: { connectionId: c.conn.id, groupId: g.id, added: added.length, removed: removed.length, renamed } });
  return toScim(c, await load(c, g.id));
}

export async function groupReplace(c: ScimCtx, id: string, body: unknown) {
  const g = await load(c, id);
  const b = z.object({ displayName: str(200).min(1), externalId: str(255).nullish(), members: z.array(z.unknown()).max(MAX_MEMBERS).optional() }).passthrough().safeParse(body);
  if (!b.success) throw new ScimError(400, "invalidSyntax", "The request body isn't a valid SCIM Group");
  return save(c, g, { displayName: b.data.displayName, externalId: b.data.externalId ?? null, members: new Set(valuesOf(b.data.members)) });
}

/** PatchOp for groups: add/remove/replace `members` (Okta and Entra forms) and replace `displayName`. */
export async function groupPatch(c: ScimCtx, id: string, body: unknown) {
  const g = await load(c, id);
  const b = z
    .object({ Operations: z.array(z.object({ op: z.string().min(1).max(20), path: str(200).optional(), value: z.unknown().optional() })).min(1).max(50) })
    .passthrough()
    .safeParse(body);
  if (!b.success) throw new ScimError(400, "invalidSyntax", "The request body isn't a valid SCIM PatchOp");
  const ch: Change = {};
  let members: Set<string> | undefined;
  const current = async () => (members ??= new Set(await memberIds(g.id)));
  for (const op of b.data.Operations) {
    const o = op.op.toLowerCase();
    if (!["add", "replace", "remove"].includes(o)) throw new ScimError(400, "invalidSyntax", `Unsupported operation "${op.op}"`);
    const path = (op.path ?? "").toLowerCase();
    const filter = op.path?.match(/^members\[\s*value\s+eq\s+"([^"]{1,100})"\s*\]$/i)?.[1];
    if (path === "members" || filter) {
      const set = await current();
      if (o === "remove") {
        if (filter) set.delete(filter);
        else if (op.value === undefined) set.clear();
        else for (const v of valuesOf(op.value)) set.delete(v);
      } else if (o === "replace") {
        members = new Set(valuesOf(op.value));
      } else for (const v of valuesOf(op.value)) set.add(v);
    } else if (path === "displayname") {
      if (typeof op.value !== "string" || !op.value.trim() || op.value.length > 200) throw new ScimError(400, "invalidValue", "displayName must be a non-empty string");
      ch.displayName = op.value.trim();
    } else if (path === "externalid") {
      ch.externalId = o === "remove" ? null : typeof op.value === "string" ? op.value.slice(0, 255) : null;
    } else if (!path && op.value && typeof op.value === "object" && !Array.isArray(op.value)) {
      const v = op.value as Record<string, unknown>;
      if (typeof v.displayName === "string" && v.displayName.trim()) ch.displayName = v.displayName.trim().slice(0, 200);
      if (v.members !== undefined) {
        const set = await current();
        if (o === "replace") members = new Set(valuesOf(v.members));
        else for (const m of valuesOf(v.members)) o === "remove" ? set.delete(m) : set.add(m);
      }
    }
  }
  if (members) ch.members = members;
  return save(c, g, ch);
}

export async function groupDelete(c: ScimCtx, id: string) {
  const g = await load(c, id);
  const ids = await memberIds(g.id);
  await db().delete(schema.scimGroups).where(eq(schema.scimGroups.id, g.id)); // members cascade
  await syncRoles(roleConn(c), ids);
  void record(c.inst.id, "scim_group.deleted", { actor: actor(c), data: { connectionId: c.conn.id, groupId: g.id, name: g.displayName } });
}
