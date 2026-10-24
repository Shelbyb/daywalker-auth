/**
 * Data layer for the platform console (/dashboard/platform): operators of the whole service.
 *
 * Roles (table `platform_staff`):
 * - "admin": everything below, plus platform settings (email/SMS providers) and managing staff.
 * - "user": every customer instance in the dashboard, site analytics, the platform audit log, and
 *   impersonation.
 *
 * Every function re-checks the role from Postgres; nothing trusts the page. Non-staff get a 404 so
 * the console's existence isn't revealed. Impersonation is recorded only in the platform audit log.
 */
import { cookies, headers } from "next/headers";
import { and, count, countDistinct, desc, eq, gt, ilike, isNotNull, sql } from "drizzle-orm";
import { z } from "zod";
import { db, schema } from "./db";
import { cache, rateLimit } from "./cache";
import { blindIndex } from "./crypto";
import { env } from "./env";
import { clientIp, errors } from "./http";
import { getDashboardUser, platformInstanceId } from "./dashboard";
import { getInstance, publishableKey } from "./auth/instance";
import { createSession, refreshCookieName } from "./auth/sessions";
import { getUser } from "./auth/users";
import { hasTwoFactor } from "./auth/mfa";
import { platformRole, type PlatformRole } from "./platform-staff";
import { recordPlatform } from "./platform-audit";
import { savePlatformSettings } from "./platform-settings";
import { deletePlan, savePlan } from "./plans";

export { platformRole, type PlatformRole };

/** Impersonation sessions are short and never renewed. */
export const IMPERSONATION_MINUTES = 30;

// ---------- Who is signed in ----------

/** The signed-in dashboard user if they are platform staff (optionally an admin); otherwise a 404. */
export async function requirePlatform(need: PlatformRole = "user") {
  const u = await getDashboardUser();
  if (!u) throw errors.unauthorized();
  const role = await platformRole(u.userId);
  if (!role || (need === "admin" && role !== "admin")) throw errors.notFound();
  return { ...u, role };
}

/** For the dashboard chrome: the role, or null (never throws). */
export async function viewerPlatformRole() {
  const u = await getDashboardUser();
  return u ? platformRole(u.userId) : null;
}

const fmtName = (u: Awaited<ReturnType<typeof getUser>>) => [u?.firstName, u?.lastName].filter(Boolean).join(" ") || null;
const primaryEmail = (u: Awaited<ReturnType<typeof getUser>>) => u?.emailAddresses.find((e) => e.primary)?.email ?? u?.emailAddresses[0]?.email ?? null;

// ---------- Analytics ----------

export async function siteAnalytics() {
  await requirePlatform();
  const now = Date.now();
  const ago = (days: number) => new Date(now - days * 86_400_000);
  const platformId = platformInstanceId() ?? "";
  const notPlatform = sql`${schema.instances.id} <> ${platformId}`;
  const [[accounts], [instances], [prodInstances], [users], [users7], [users30], [sessions]] = await Promise.all([
    db().select({ n: count() }).from(schema.accounts),
    db().select({ n: count() }).from(schema.instances).where(notPlatform),
    db().select({ n: count() }).from(schema.instances).where(and(notPlatform, eq(schema.instances.environment, "production"))),
    db().select({ n: count() }).from(schema.users).where(sql`${schema.users.instanceId} <> ${platformId}`),
    db().select({ n: count() }).from(schema.users).where(and(sql`${schema.users.instanceId} <> ${platformId}`, gt(schema.users.createdAt, ago(7)))),
    db().select({ n: count() }).from(schema.users).where(and(sql`${schema.users.instanceId} <> ${platformId}`, gt(schema.users.createdAt, ago(30)))),
    db().select({ n: count() }).from(schema.sessions).where(and(eq(schema.sessions.status, "active"), gt(schema.sessions.expiresAt, new Date()))),
  ]);
  const a = schema.auditEvents;
  const signIns = (days: number) =>
    db().select({ n: count(), people: countDistinct(a.targetId) }).from(a).where(and(eq(a.type, "user.signed_in"), gt(a.createdAt, ago(days)), sql`${a.instanceId} <> ${platformId}`));
  const [[d1], [d7], [d30], [failed7]] = await Promise.all([
    signIns(1),
    signIns(7),
    signIns(30),
    db().select({ n: count() }).from(a).where(and(eq(a.type, "user.sign_in_failed"), gt(a.createdAt, ago(7)))),
  ]);
  const day = sql<string>`to_char(date_trunc('day', ${schema.users.createdAt}), 'YYYY-MM-DD')`;
  const signupRows = await db()
    .select({ day, n: count() })
    .from(schema.users)
    .where(and(gt(schema.users.createdAt, ago(14)), sql`${schema.users.instanceId} <> ${platformId}`))
    .groupBy(day);
  const signInDay = sql<string>`to_char(date_trunc('day', ${a.createdAt}), 'YYYY-MM-DD')`;
  const signInRows = await db()
    .select({ day: signInDay, n: count() })
    .from(a)
    .where(and(eq(a.type, "user.signed_in"), gt(a.createdAt, ago(14)), sql`${a.instanceId} <> ${platformId}`))
    .groupBy(signInDay);
  const days = Array.from({ length: 14 }, (_, i) => new Date(now - (13 - i) * 86_400_000).toISOString().slice(0, 10));
  const top = await db()
    .select({ id: schema.instances.id, name: schema.instances.name, environment: schema.instances.environment, users: count(schema.users.id) })
    .from(schema.instances)
    .leftJoin(schema.users, eq(schema.users.instanceId, schema.instances.id))
    .where(notPlatform)
    .groupBy(schema.instances.id)
    .orderBy(desc(count(schema.users.id)))
    .limit(10);
  return {
    accounts: accounts.n,
    instances: instances.n,
    productionInstances: prodInstances.n,
    users: users.n,
    newUsers7d: users7.n,
    newUsers30d: users30.n,
    activeSessions: sessions.n,
    signIns: { d1: d1.n, d7: d7.n, d30: d30.n, active1d: d1.people, active7d: d7.people, active30d: d30.people },
    failedSignIns7d: failed7.n,
    daily: days.map((d) => ({ day: d, signUps: signupRows.find((r) => r.day === d)?.n ?? 0, signIns: signInRows.find((r) => r.day === d)?.n ?? 0 })),
    topInstances: top,
  };
}

// ---------- Every instance ----------

export async function allInstances(q: { search?: string; limit?: number; offset?: number } = {}) {
  await requirePlatform();
  const limit = Math.min(Math.max(q.limit ?? 50, 1), 100);
  const platformId = platformInstanceId() ?? "";
  const conds = [sql`${schema.instances.id} <> ${platformId}`];
  const s = q.search?.trim().slice(0, 100);
  if (s) conds.push(s.startsWith("ins_") ? eq(schema.instances.id, s) : ilike(schema.instances.name, `%${s.replace(/[%_\\]/g, "\\$&")}%`));
  const rows = await db()
    .select({ id: schema.instances.id, name: schema.instances.name, environment: schema.instances.environment, accountId: schema.instances.accountId, accountName: schema.accounts.name, createdAt: schema.instances.createdAt, users: count(schema.users.id) })
    .from(schema.instances)
    .innerJoin(schema.accounts, eq(schema.accounts.id, schema.instances.accountId))
    .leftJoin(schema.users, eq(schema.users.instanceId, schema.instances.id))
    .where(and(...conds))
    .groupBy(schema.instances.id, schema.accounts.name)
    .orderBy(desc(schema.instances.createdAt))
    .limit(limit)
    .offset(Math.max(q.offset ?? 0, 0));
  return rows;
}

/** Users of one customer instance, for the impersonation picker. Search is by exact email (blind index) or user ID. */
export async function instanceUsers(instanceId: string, q: { search?: string; limit?: number; offset?: number } = {}) {
  await requirePlatform();
  const inst = await customerInstance(instanceId);
  const limit = Math.min(Math.max(q.limit ?? 25, 1), 100);
  const s = q.search?.trim().toLowerCase().slice(0, 254);
  let ids: string[];
  if (s) {
    if (s.startsWith("user_")) {
      ids = (await db().select({ id: schema.users.id }).from(schema.users).where(and(eq(schema.users.instanceId, inst.id), eq(schema.users.id, s)))).map((r) => r.id);
    } else {
      const idx = blindIndex(s, `email:${inst.id}`);
      ids = (await db().select({ id: schema.emailAddresses.userId }).from(schema.emailAddresses).where(and(eq(schema.emailAddresses.instanceId, inst.id), eq(schema.emailAddresses.emailIndex, idx)))).map((r) => r.id);
    }
  } else {
    ids = (await db().select({ id: schema.users.id }).from(schema.users).where(eq(schema.users.instanceId, inst.id)).orderBy(desc(schema.users.createdAt)).limit(limit).offset(Math.max(q.offset ?? 0, 0))).map((r) => r.id);
  }
  const users = await Promise.all(ids.map((id) => getUser(inst.id, id, { includePrivate: true })));
  return {
    instance: { id: inst.id, name: inst.name, environment: inst.environment, accountId: inst.accountId },
    users: users.filter((u) => !!u).map((u) => ({
      id: u!.id,
      email: primaryEmail(u),
      name: fmtName(u),
      banned: !!(u as { banned?: boolean }).banned,
      twoFactorEnabled: u!.twoFactorEnabled,
      lastSignInAt: u!.lastSignInAt,
      createdAt: u!.createdAt,
    })),
  };
}

/** A customer instance. The platform instance itself is off limits (its users are the staff and developers). */
async function customerInstance(instanceId: string) {
  if (typeof instanceId !== "string" || !/^ins_[0-9a-z]{22}$/.test(instanceId)) throw errors.notFound("Instance not found");
  const inst = await getInstance(instanceId);
  if (!inst || inst.id === platformInstanceId()) throw errors.notFound("Instance not found");
  return inst;
}

// ---------- Impersonation ----------

const reasonInput = z.string().trim().min(10, "Give a reason of at least 10 characters (it goes in the platform audit log)").max(500);

/**
 * Opens a short session as `targetUserId` in a customer instance and sets its refresh cookie on this
 * browser, so the hosted pages and the customer's app see that user. Requirements:
 * - platform staff with two-factor turned on, rate limited;
 * - a reason, stored (encrypted) in the platform audit log;
 * - never the platform instance, never a suspended user.
 * The session is invisible to the customer: no instance audit entry, no webhook, hidden from the
 * user's session list, and it doesn't count as a sign-in. It lasts IMPERSONATION_MINUTES.
 */
export async function startImpersonation(instanceId: string, targetUserId: string, rawReason: string) {
  const staff = await requirePlatform();
  const reason = reasonInput.parse(rawReason);
  const h = await headers();
  const ip = clientIp(new Request(env().APP_URL, { headers: h }));
  const userAgent = h.get("user-agent")?.slice(0, 200) ?? null;
  const deny = async (why: string, msg: string) => {
    void recordPlatform("impersonation.denied", { actorId: staff.userId, instanceId, target: targetUserId, data: { why, ip, userAgent } });
    return errors.forbidden(msg);
  };
  if (!(await hasTwoFactor(staff.userId))) throw await deny("staff_without_two_factor", "Turn on two-factor for your own account before impersonating anyone");
  if ((await rateLimit(`platform:impersonate:${staff.userId}`, 20, 3600)) < 0) throw errors.tooMany();
  const inst = await customerInstance(instanceId);
  const target = await getUser(inst.id, String(targetUserId).slice(0, 100), { includePrivate: true });
  if (!target) throw errors.notFound("User not found");
  if ((target as { banned?: boolean }).banned) throw await deny("target_suspended", "This user is suspended. Restore them first");
  const s = await createSession(inst, target.id, { ip, userAgent, impersonatorId: staff.userId, lifetimeMs: IMPERSONATION_MINUTES * 60_000 });
  const secure = env().APP_URL.startsWith("https://");
  (await cookies()).set(refreshCookieName(inst.id), s.refreshToken, { httpOnly: true, secure, sameSite: secure ? "none" : "lax", path: "/v1/client", expires: s.expiresAt });
  void recordPlatform("impersonation.started", {
    actorId: staff.userId,
    instanceId: inst.id,
    target: target.id,
    data: { reason, sessionId: s.id, instanceName: inst.name, userEmail: primaryEmail(target), expiresAt: s.expiresAt.toISOString(), ip, userAgent },
  });
  return { sessionId: s.id, expiresAt: s.expiresAt, accountUrl: `/account?pk=${encodeURIComponent(publishableKey(inst))}` };
}

/** Impersonation sessions still running. Staff see their own; admins see everyone's. */
export async function activeImpersonations() {
  const staff = await requirePlatform();
  const t = schema.sessions;
  const conds = [isNotNull(t.impersonatorId), eq(t.status, "active"), gt(t.expiresAt, new Date())];
  if (staff.role !== "admin") conds.push(eq(t.impersonatorId, staff.userId));
  const rows = await db()
    .select({ id: t.id, instanceId: t.instanceId, userId: t.userId, impersonatorId: t.impersonatorId, createdAt: t.createdAt, expiresAt: t.expiresAt, instanceName: schema.instances.name })
    .from(t)
    .innerJoin(schema.instances, eq(schema.instances.id, t.instanceId))
    .where(and(...conds))
    .orderBy(desc(t.createdAt))
    .limit(100);
  return rows;
}

/** Ends one impersonation session (own, or anyone's for admins). */
export async function endImpersonation(sessionId: string) {
  const staff = await requirePlatform();
  const t = schema.sessions;
  const conds = [eq(t.id, String(sessionId).slice(0, 100)), isNotNull(t.impersonatorId), eq(t.status, "active")];
  if (staff.role !== "admin") conds.push(eq(t.impersonatorId, staff.userId));
  const [row] = await db().update(t).set({ status: "revoked" }).where(and(...conds)).returning({ h: t.refreshTokenHash, instanceId: t.instanceId, userId: t.userId, impersonatorId: t.impersonatorId });
  if (!row) throw errors.notFound("Session not found");
  await cache().del(`sess:${row.h}`);
  void recordPlatform("impersonation.ended", { actorId: staff.userId, instanceId: row.instanceId, target: row.userId, data: { sessionId, startedBy: row.impersonatorId } });
}

// ---------- Staff ----------

export async function listStaff() {
  await requirePlatform("admin");
  const pid = platformInstanceId();
  const rows = await db().select().from(schema.platformStaff).orderBy(desc(schema.platformStaff.createdAt));
  const users = pid ? await Promise.all(rows.map((r) => getUser(pid, r.userId))) : [];
  return rows.map((r, i) => ({ userId: r.userId, role: r.role, email: primaryEmail(users[i] ?? null), name: fmtName(users[i] ?? null), twoFactorEnabled: !!users[i]?.twoFactorEnabled, createdAt: r.createdAt }));
}

const roleInput = z.enum(["admin", "user"]);

/** Adds a dashboard user (found by email in the platform instance) to the staff, or changes their role. */
export async function setStaff(email: string, rawRole: string) {
  const staff = await requirePlatform("admin");
  const role = roleInput.parse(rawRole);
  const pid = platformInstanceId();
  if (!pid) throw errors.notFound();
  const e = z.string().trim().toLowerCase().email("Enter an email address").max(254).parse(email);
  const [hit] = await db()
    .select({ userId: schema.emailAddresses.userId })
    .from(schema.emailAddresses)
    .where(and(eq(schema.emailAddresses.instanceId, pid), eq(schema.emailAddresses.emailIndex, blindIndex(e, `email:${pid}`))));
  if (!hit) throw errors.badRequest("no_such_user", "Nobody with that email has signed in to the dashboard yet. Ask them to sign in once first");
  if (hit.userId === staff.userId) throw errors.badRequest("own_role", "You can't change your own role");
  const before = await platformRole(hit.userId);
  await db().insert(schema.platformStaff).values({ userId: hit.userId, role, createdBy: staff.userId }).onConflictDoUpdate({ target: schema.platformStaff.userId, set: { role } });
  void recordPlatform(before ? "staff.role_changed" : "staff.added", { actorId: staff.userId, target: hit.userId, data: { email: e, role, previousRole: before } });
}

export async function removeStaff(userId: string) {
  const staff = await requirePlatform("admin");
  if (userId === staff.userId) throw errors.badRequest("own_role", "You can't remove yourself");
  const [row] = await db().delete(schema.platformStaff).where(eq(schema.platformStaff.userId, String(userId).slice(0, 100))).returning({ role: schema.platformStaff.role });
  if (!row) throw errors.notFound("Not on the staff");
  // Their running impersonation sessions end with their access.
  const ended = await db()
    .update(schema.sessions)
    .set({ status: "revoked" })
    .where(and(eq(schema.sessions.impersonatorId, userId), eq(schema.sessions.status, "active")))
    .returning({ h: schema.sessions.refreshTokenHash });
  if (ended.length) await cache().del(...ended.map((r) => `sess:${r.h}`));
  void recordPlatform("staff.removed", { actorId: staff.userId, target: userId, data: { role: row.role, impersonationsEnded: ended.length } });
}

// ---------- Platform settings ----------

export async function updatePlatformSettings(raw: unknown) {
  const staff = await requirePlatform("admin");
  const changed = await savePlatformSettings(staff.userId, raw);
  if (changed.length) void recordPlatform("platform_settings.updated", { actorId: staff.userId, data: { changed } });
  return changed;
}

/** Display names for actor IDs in the platform audit log. */
export async function staffNames(ids: (string | null)[]) {
  const pid = platformInstanceId();
  const uniq = [...new Set(ids.filter((x): x is string => !!x))];
  const out: Record<string, string> = {};
  if (!pid) return out;
  await Promise.all(uniq.map(async (id) => {
    const u = await getUser(pid, id);
    out[id] = primaryEmail(u) ?? id;
  }));
  return out;
}

/** Instance IDs to names, for the audit log. */
export async function instanceNames(ids: (string | null)[]) {
  const uniq = [...new Set(ids.filter((x): x is string => !!x))];
  const out: Record<string, string> = {};
  await Promise.all(uniq.map(async (id) => {
    const i = await getInstance(id).catch(() => null);
    if (i) out[id] = i.name;
  }));
  return out;
}

export async function adminSavePlan(input: Parameters<typeof savePlan>[0]) {
  const staff = await requirePlatform("admin");
  const id = await savePlan(input);
  void recordPlatform("plan.saved", { actorId: staff.userId, target: id, data: { name: input.name, priceCents: input.priceCents } });
  return id;
}

export async function adminDeletePlan(id: string) {
  const staff = await requirePlatform("admin");
  await deletePlan(id);
  void recordPlatform("plan.deleted", { actorId: staff.userId, target: id });
}
