import { and, eq, gt, isNull, count } from "drizzle-orm";
import { hasTwoFactor } from "./mfa";
import { forgetOrgPolicy } from "./two-factor-policy";
import { db, schema } from "../db";
import { cache, rateLimit } from "../cache";
import { blindIndex, decrypt, encrypt } from "../crypto";
import { newId, newToken, sha256 } from "../ids";
import { errors } from "../http";
import { env } from "../env";
import { sendMail } from "../mail";
import { composeEmail } from "../email-templates";
import { getUser } from "./users";
import { publishableKey } from "./instance";
import type { Instance } from "../db/schema";
import { emit } from "../webhooks";

export type OrgRole = "admin" | "member";

/** What each role may do. Checked on every organization action, server-side. */
export const ROLE_PERMISSIONS: Record<OrgRole, string[]> = {
  admin: ["org:read", "org:manage", "members:read", "members:manage", "invitations:manage"],
  member: ["org:read", "members:read"],
};

const INVITE_TTL_DAYS = 7;
const emailIndexFor = (instanceId: string, email: string) => blindIndex(email, `email:${instanceId}`);
const memKey = (orgId: string, userId: string) => `mem:${orgId}:${userId}`;

function slugify(name: string) {
  return name.toLowerCase().normalize("NFKD").replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "").slice(0, 40) || "org";
}

// ---------- Membership lookups ----------

/** The user's role in an org of this instance, or null. Cached briefly; invalidated on change. */
export async function roleIn(instanceId: string, orgId: string, userId: string): Promise<OrgRole | null> {
  const hit = await cache().get(memKey(orgId, userId));
  if (hit) return hit === "-" ? null : (hit as OrgRole);
  const [row] = await db()
    .select({ role: schema.memberships.role })
    .from(schema.memberships)
    .innerJoin(schema.organizations, eq(schema.organizations.id, schema.memberships.orgId))
    .where(and(eq(schema.memberships.orgId, orgId), eq(schema.memberships.userId, userId), eq(schema.organizations.instanceId, instanceId)));
  await cache().set(memKey(orgId, userId), row?.role ?? "-", "EX", 60);
  return row?.role ?? null;
}

const dropRole = (orgId: string, userId: string) => cache().del(memKey(orgId, userId));

/** Throws 404 for non-members (no probing of org IDs) and 403 when the role lacks the permission. */
export async function requirePermission(instanceId: string, orgId: string, userId: string, permission: string) {
  const role = await roleIn(instanceId, orgId, userId);
  if (!role) throw errors.notFound("Organization not found");
  if (!ROLE_PERMISSIONS[role].includes(permission)) throw errors.forbidden("Your role doesn't allow this");
  return role;
}

async function adminCount(orgId: string) {
  const [r] = await db()
    .select({ n: count() })
    .from(schema.memberships)
    .where(and(eq(schema.memberships.orgId, orgId), eq(schema.memberships.role, "admin")));
  return Number(r?.n ?? 0);
}

// ---------- Organizations ----------

export async function createOrg(inst: Instance, userId: string, name: string) {
  if ((await rateLimit(`${inst.id}:org_create:${userId}`, 10, 3600)) < 0) throw errors.tooMany();
  const id = newId("org");
  const base = slugify(name);
  for (let attempt = 0; attempt < 5; attempt++) {
    const slug = attempt === 0 ? base : `${base}-${newToken(3).toLowerCase().replace(/[^a-z0-9]/g, "")}`;
    try {
      await db().transaction(async (tx) => {
        await tx.insert(schema.organizations).values({ id, instanceId: inst.id, name, slug, createdBy: userId });
        await tx.insert(schema.memberships).values({ orgId: id, userId, role: "admin" });
      });
      void emit(inst.id, "organization.created", { organizationId: id, name, slug, createdBy: userId });
      void emit(inst.id, "organizationMembership.created", { organizationId: id, userId, role: "admin" });
      return { id, name, slug };
    } catch (e) {
      const code = (e as { cause?: { code?: string } }).cause?.code ?? (e as { code?: string }).code;
      if (code !== "23505") throw e; // slug taken: retry with a suffix
    }
  }
  throw errors.conflict("slug_taken", "Couldn't find a free name for this organization");
}

export async function myOrgs(instanceId: string, userId: string) {
  return db()
    .select({ id: schema.organizations.id, name: schema.organizations.name, slug: schema.organizations.slug, role: schema.memberships.role, requireTwoFactor: schema.organizations.requireTwoFactor })
    .from(schema.memberships)
    .innerJoin(schema.organizations, eq(schema.organizations.id, schema.memberships.orgId))
    .where(and(eq(schema.memberships.userId, userId), eq(schema.organizations.instanceId, instanceId)));
}

export async function getOrg(instanceId: string, orgId: string) {
  const [o] = await db()
    .select()
    .from(schema.organizations)
    .where(and(eq(schema.organizations.id, orgId), eq(schema.organizations.instanceId, instanceId)));
  return o ?? null;
}

export async function renameOrg(instanceId: string, orgId: string, actorId: string, name: string) {
  await requirePermission(instanceId, orgId, actorId, "org:manage");
  await db().update(schema.organizations).set({ name }).where(eq(schema.organizations.id, orgId));
}

/** Admins only. Turning it on needs two-factor yourself, so you can't lock yourself out of your own organization. */
export async function setOrgTwoFactor(instanceId: string, orgId: string, actorId: string | null, required: boolean) {
  if (actorId) {
    await requirePermission(instanceId, orgId, actorId, "org:manage");
    if (required && !(await hasTwoFactor(actorId))) throw errors.badRequest("two_factor_required_first", "Turn on two-step verification for your own account first");
  } else if (!(await getOrg(instanceId, orgId))) throw errors.notFound("Organization not found");
  await db().update(schema.organizations).set({ requireTwoFactor: required }).where(and(eq(schema.organizations.id, orgId), eq(schema.organizations.instanceId, instanceId)));
  await forgetOrgPolicy(orgId);
}

export async function deleteOrg(instanceId: string, orgId: string, actorId: string) {
  await requirePermission(instanceId, orgId, actorId, "org:manage");
  const members = await db().select({ u: schema.memberships.userId }).from(schema.memberships).where(eq(schema.memberships.orgId, orgId));
  await db().delete(schema.organizations).where(eq(schema.organizations.id, orgId));
  await Promise.all(members.map((m) => dropRole(orgId, m.u)));
  void emit(instanceId, "organization.deleted", { organizationId: orgId });
}

// ---------- Members ----------

export async function listMembers(instanceId: string, orgId: string, actorId: string) {
  await requirePermission(instanceId, orgId, actorId, "members:read");
  const rows = await db().select().from(schema.memberships).where(eq(schema.memberships.orgId, orgId)).limit(500);
  return Promise.all(
    rows.map(async (m) => {
      const u = await getUser(instanceId, m.userId);
      return {
        userId: m.userId,
        role: m.role,
        joinedAt: m.createdAt,
        email: u?.emailAddresses.find((e) => e.primary)?.email ?? null,
        name: [u?.firstName, u?.lastName].filter(Boolean).join(" ") || null,
      };
    }),
  );
}

export async function changeRole(instanceId: string, orgId: string, actorId: string, targetId: string, role: OrgRole) {
  await requirePermission(instanceId, orgId, actorId, "members:manage");
  const current = await roleIn(instanceId, orgId, targetId);
  if (!current) throw errors.notFound("Member not found");
  if (current === "admin" && role !== "admin" && (await adminCount(orgId)) <= 1)
    throw errors.badRequest("last_admin", "An organization needs at least one admin");
  await db().update(schema.memberships).set({ role }).where(and(eq(schema.memberships.orgId, orgId), eq(schema.memberships.userId, targetId)));
  await dropRole(orgId, targetId);
  void emit(instanceId, "organizationMembership.deleted", { organizationId: orgId, userId: targetId });
}

/** Admins remove others; anyone may remove themselves (leave). The last admin can't leave. */
export async function removeMember(instanceId: string, orgId: string, actorId: string, targetId: string) {
  if (actorId !== targetId) await requirePermission(instanceId, orgId, actorId, "members:manage");
  const current = await roleIn(instanceId, orgId, targetId);
  if (!current) throw errors.notFound("Member not found");
  if (current === "admin" && (await adminCount(orgId)) <= 1)
    throw errors.badRequest("last_admin", "An organization needs at least one admin. Promote someone else first, or delete the organization");
  await db().delete(schema.memberships).where(and(eq(schema.memberships.orgId, orgId), eq(schema.memberships.userId, targetId)));
  await dropRole(orgId, targetId);
}

// ---------- Invitations ----------

export async function invite(inst: Instance, orgId: string, actorId: string, email: string, role: OrgRole) {
  await requirePermission(inst.id, orgId, actorId, "invitations:manage");
  if ((await rateLimit(`${inst.id}:invite:${orgId}`, 50, 3600)) < 0) throw errors.tooMany();
  const org = (await getOrg(inst.id, orgId))!;
  const idx = emailIndexFor(inst.id, email);

  // Already a member?
  const [existing] = await db()
    .select({ u: schema.memberships.userId })
    .from(schema.emailAddresses)
    .innerJoin(schema.memberships, and(eq(schema.memberships.userId, schema.emailAddresses.userId), eq(schema.memberships.orgId, orgId)))
    .where(and(eq(schema.emailAddresses.instanceId, inst.id), eq(schema.emailAddresses.emailIndex, idx)));
  if (existing) throw errors.conflict("already_member", "That person is already a member");

  // One live invitation per address: re-inviting replaces the old link.
  await db()
    .update(schema.invitations)
    .set({ revokedAt: new Date() })
    .where(and(eq(schema.invitations.orgId, orgId), eq(schema.invitations.emailIndex, idx), isNull(schema.invitations.acceptedAt), isNull(schema.invitations.revokedAt)));

  const token = newToken(32);
  const id = newId("inv");
  await db().insert(schema.invitations).values({
    id,
    orgId,
    emailEnc: encrypt(email, `invitations.email:${id}`),
    emailIndex: idx,
    role,
    tokenHash: sha256(token),
    invitedBy: actorId,
    expiresAt: new Date(Date.now() + INVITE_TTL_DAYS * 86_400_000),
  });
  const link = `${env().APP_URL}/accept-invite?pk=${encodeURIComponent(publishableKey(inst))}&token=${encodeURIComponent(token)}`;
  const inviter = await getUser(inst.id, actorId);
  const inviterName = [inviter?.firstName, inviter?.lastName].filter(Boolean).join(" ") || inviter?.emailAddresses[0]?.email || "Someone";
  await sendMail({ to: email, ...(await composeEmail(inst, "invitation", { org_name: org.name, inviter: inviterName, link, expires_days: String(INVITE_TTL_DAYS) })) });
  void emit(inst.id, "organizationInvitation.created", { organizationId: orgId, invitationId: id, email, role });
  return { id, email, role, expiresAt: new Date(Date.now() + INVITE_TTL_DAYS * 86_400_000) };
}

export async function listInvitations(instanceId: string, orgId: string, actorId: string) {
  await requirePermission(instanceId, orgId, actorId, "invitations:manage");
  const rows = await db()
    .select()
    .from(schema.invitations)
    .where(and(eq(schema.invitations.orgId, orgId), isNull(schema.invitations.acceptedAt), isNull(schema.invitations.revokedAt), gt(schema.invitations.expiresAt, new Date())));
  return rows.map((i) => ({ id: i.id, email: decrypt(i.emailEnc, `invitations.email:${i.id}`), role: i.role, expiresAt: i.expiresAt, createdAt: i.createdAt }));
}

export async function revokeInvitation(instanceId: string, orgId: string, actorId: string, invitationId: string) {
  await requirePermission(instanceId, orgId, actorId, "invitations:manage");
  const rows = await db()
    .update(schema.invitations)
    .set({ revokedAt: new Date() })
    .where(and(eq(schema.invitations.id, invitationId), eq(schema.invitations.orgId, orgId), isNull(schema.invitations.acceptedAt)))
    .returning({ id: schema.invitations.id });
  if (!rows.length) throw errors.notFound("Invitation not found");
}

/** What an invite link points at, for the accept page (no secrets, no email shown). */
export async function previewInvitation(instanceId: string, token: string) {
  const [row] = await db()
    .select({ inv: schema.invitations, org: schema.organizations })
    .from(schema.invitations)
    .innerJoin(schema.organizations, eq(schema.organizations.id, schema.invitations.orgId))
    .where(and(eq(schema.invitations.tokenHash, sha256(token)), eq(schema.organizations.instanceId, instanceId)));
  if (!row || row.inv.acceptedAt || row.inv.revokedAt || row.inv.expiresAt <= new Date()) return null;
  return { orgName: row.org.name, role: row.inv.role };
}

/**
 * The link alone isn't enough: the signed-in user must own the invited address, and it
 * must be verified. A forwarded or leaked link can't be used by someone else.
 */
export async function acceptInvitation(instanceId: string, userId: string, token: string) {
  const invalid = () => errors.badRequest("invalid_invitation", "This invitation is invalid, expired or was already used");
  const [row] = await db()
    .select({ inv: schema.invitations, org: schema.organizations })
    .from(schema.invitations)
    .innerJoin(schema.organizations, eq(schema.organizations.id, schema.invitations.orgId))
    .where(and(eq(schema.invitations.tokenHash, sha256(token)), eq(schema.organizations.instanceId, instanceId)));
  if (!row || row.inv.acceptedAt || row.inv.revokedAt || row.inv.expiresAt <= new Date()) throw invalid();

  const [mine] = await db()
    .select({ verifiedAt: schema.emailAddresses.verifiedAt })
    .from(schema.emailAddresses)
    .where(and(eq(schema.emailAddresses.userId, userId), eq(schema.emailAddresses.emailIndex, row.inv.emailIndex)));
  if (!mine) throw errors.forbidden("This invitation was sent to a different email address").withCode("invitation_email_mismatch");
  if (!mine.verifiedAt) throw errors.forbidden("Verify your email address first, then open the invitation again").withCode("email_unverified");

  // Mark used first (conditional update = single use under concurrency), then add membership.
  const used = await db()
    .update(schema.invitations)
    .set({ acceptedAt: new Date() })
    .where(and(eq(schema.invitations.id, row.inv.id), isNull(schema.invitations.acceptedAt), isNull(schema.invitations.revokedAt)))
    .returning({ id: schema.invitations.id });
  if (!used.length) throw invalid();
  await db().insert(schema.memberships).values({ orgId: row.org.id, userId, role: row.inv.role }).onConflictDoNothing();
  await dropRole(row.org.id, userId);
  void emit(instanceId, "organizationMembership.created", { organizationId: row.org.id, userId, role: row.inv.role });
  return { id: row.org.id, name: row.org.name, slug: row.org.slug, role: (await roleIn(instanceId, row.org.id, userId))! };
}

// ---------- Active organization (carried in the session JWT) ----------

export async function setActiveOrg(instanceId: string, sessionId: string, refreshHash: string, userId: string, orgId: string | null) {
  if (orgId && !(await roleIn(instanceId, orgId, userId))) throw errors.notFound("Organization not found");
  await db().update(schema.sessions).set({ activeOrgId: orgId }).where(eq(schema.sessions.id, sessionId));
  await cache().del(`sess:${refreshHash}`); // next token mint re-reads the active org
}
