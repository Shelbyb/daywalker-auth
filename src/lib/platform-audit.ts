/**
 * Platform audit log: what platform staff did (impersonation, opening customer instances, platform
 * settings, staff changes). Separate from the per-instance audit log on purpose: customers never
 * see it, and only platform staff can read it. Like `record`, it never throws. Details are encrypted.
 */
import { and, desc, eq, lt, sql } from "drizzle-orm";
import { db, schema } from "./db";
import { decrypt, encrypt } from "./crypto";
import { newId } from "./ids";

export const PLATFORM_AUDIT_TYPES = [
  "impersonation.started", "impersonation.ended", "impersonation.denied",
  "instance.accessed",
  "platform_settings.updated",
  "plan.saved", "plan.deleted", "staff.added", "staff.role_changed", "staff.removed",
] as const;
export type PlatformAuditType = (typeof PLATFORM_AUDIT_TYPES)[number];

/** Longer than the instance log: this is the record of what operators did with customer data. */
export const PLATFORM_RETENTION_DAYS = 365;
const ctx = (id: string) => `platform_audit_events.data:${id}`;

export async function recordPlatform(
  type: PlatformAuditType,
  e: { actorId: string; instanceId?: string | null; target?: string | null; data?: Record<string, unknown> },
) {
  try {
    const id = newId("paud");
    await db().insert(schema.platformAuditEvents).values({
      id,
      type,
      actorId: e.actorId,
      instanceId: e.instanceId ?? null,
      targetId: e.target ?? null,
      dataEnc: e.data && Object.keys(e.data).length ? encrypt(JSON.stringify(e.data), ctx(id)) : null,
    });
  } catch (err) {
    console.error("[platform-audit] failed to record", type, (err as Error).message);
  }
}

export type PlatformAuditQuery = { limit?: number; before?: string; type?: string; actor?: string; instance?: string; target?: string };

/** Newest first. `before` is the `nextCursor` of the previous page. */
export async function listPlatformAudit(q: PlatformAuditQuery = {}) {
  const limit = Math.min(Math.max(q.limit ?? 50, 1), 200);
  const t = schema.platformAuditEvents;
  const conds = [];
  if (q.type) conds.push(eq(t.type, q.type));
  if (q.actor) conds.push(eq(t.actorId, q.actor));
  if (q.instance) conds.push(eq(t.instanceId, q.instance));
  if (q.target) conds.push(eq(t.targetId, q.target));
  if (q.before) conds.push(sql`(${t.createdAt}, ${t.id}) < (select c.created_at, c.id from platform_audit_events c where c.id = ${q.before})`);
  const rows = await db().select().from(t).where(conds.length ? and(...conds) : undefined).orderBy(desc(t.createdAt), desc(t.id)).limit(limit + 1);
  const page = rows.slice(0, limit);
  return {
    data: page.map((r) => {
      let data: Record<string, unknown> | null = null;
      if (r.dataEnc) {
        try {
          data = JSON.parse(decrypt(r.dataEnc, ctx(r.id)));
        } catch {
          data = null;
        }
      }
      return { id: r.id, type: r.type, actorId: r.actorId, instanceId: r.instanceId, target: r.targetId, data, createdAt: r.createdAt };
    }),
    nextCursor: rows.length > limit ? page[page.length - 1].id : null,
  };
}

export async function purgePlatformAudit() {
  await db().delete(schema.platformAuditEvents).where(lt(schema.platformAuditEvents.createdAt, new Date(Date.now() - PLATFORM_RETENTION_DAYS * 86_400_000)));
}
