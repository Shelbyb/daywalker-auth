/**
 * Audit log. `record` never throws and never blocks the request: a logging hiccup must not break
 * a sign-in, and the log must not slow one down. Personal data goes in `data`, which is encrypted.
 */
import { and, desc, eq, lt, lte, sql } from "drizzle-orm";
import { db, schema } from "./db";
import { decrypt, encrypt } from "./crypto";
import { dataDigestOf, entryHash, GENESIS_HASH } from "./audit-chain";
import { newId } from "./ids";

export const AUDIT_TYPES = [
  "user.signed_up", "user.signed_in", "user.sign_in_failed", "user.sign_in_blocked", "user.signed_out",
  "user.password_changed", "user.password_reset", "user.profile_updated",
  "user.two_factor_enabled", "user.two_factor_disabled", "user.two_factor_reset", "user.two_factor_failed",
  "user.passkey_added", "user.passkey_removed",
  "session.device_bound", "user.reverified", "audit.exported", "audit.verified", "audit_export.configured", "audit_export.removed", "user.banned", "user.unbanned", "user.deleted", "user.locked", "user.unlocked", "user.deletion_requested", "user.deletion_canceled", "user.data_exported",
  "api_key.created", "api_key.revoked", "signing_key.rotated",
  "instance.settings_updated", "instance.terms_updated", "instance.organizations_updated", "instance.sessions_updated", "instance.branding_updated", "instance.domain_added", "instance.domain_verified", "instance.config_cloned", "m2m_client.created", "m2m_client.updated", "m2m_client.deleted", "m2m_client.secret_rotated", "user_api_key.created", "user_api_key.revoked", "instance.test_mode_updated", "satellite_domain.added", "satellite_domain.verified", "satellite_domain.removed", "instance.primary_domain_updated",
  "social_provider.saved", "social_provider.enabled", "social_provider.disabled",
  "sso_connection.created", "sso_connection.updated", "sso_connection.deleted",
  "scim_token.created", "scim_token.revoked",
  "scim_group.created", "scim_group.updated", "scim_group.deleted", "scim_role.changed",
  "scim_user.created", "scim_user.updated", "scim_user.deactivated", "scim_user.reactivated", "scim_user.deleted",
  "email_template.updated", "email_template.reset", "email_template.test_sent",
  "org_role.created", "org_role.updated", "org_role.deleted", "org_domain.added", "org_domain.verified", "org_domain.updated", "org_domain.removed", "org_domain.joined",
  "webhook.created", "webhook.updated", "webhook.secret_rotated", "webhook.deleted",
] as const;
export type AuditType = (typeof AUDIT_TYPES)[number];

export type Actor = { type: "user" | "developer" | "api" | "system"; id?: string | null };
export const RETENTION_DAYS = 90;
const ctx = (id: string) => `audit_events.data:${id}`;

/** In-process queue per instance, so a burst of events waits here instead of holding a connection each while they wait for the chain lock. */
const queues = new Map<string, Promise<unknown>>();

/**
 * Appends to the instance's hash chain (see audit-chain.ts). The chain head row is locked for the
 * length of one small transaction, which also serializes appends across server processes.
 */
async function append(instanceId: string, type: AuditType, e: { actor?: Actor; target?: string | null; data?: Record<string, unknown> }) {
  const id = newId("aud");
  const plaintext = e.data && Object.keys(e.data).length ? JSON.stringify(e.data) : null;
  const dataDigest = dataDigestOf(instanceId, plaintext);
  const actorType = e.actor?.type ?? "system";
  const actorId = e.actor?.id ?? null;
  const targetId = e.target ?? null;
  await db().transaction(async (tx) => {
    await tx.insert(schema.auditChains).values({ instanceId }).onConflictDoNothing();
    const [head] = await tx.select().from(schema.auditChains).where(eq(schema.auditChains.instanceId, instanceId)).for("update");
    const seq = head.seq + 1;
    const prevHash = head.seq === 0 && head.purgedSeq === 0 ? GENESIS_HASH : head.hash;
    const createdAt = new Date();
    const hash = entryHash({ instanceId, seq, prevHash, id, type, actorType, actorId, targetId, createdAt, dataDigest });
    await tx.insert(schema.auditEvents).values({ id, instanceId, type, actorType, actorId, targetId, dataEnc: plaintext === null ? null : encrypt(plaintext, ctx(id)), seq, prevHash, hash, dataDigest, createdAt });
    await tx.update(schema.auditChains).set({ seq, hash, updatedAt: new Date() }).where(eq(schema.auditChains.instanceId, instanceId));
  });
}

export async function record(
  instanceId: string,
  type: AuditType,
  e: { actor?: Actor; target?: string | null; data?: Record<string, unknown> } = {},
) {
  const run = (queues.get(instanceId) ?? Promise.resolve())
    .catch(() => undefined)
    .then(() => append(instanceId, type, e))
    .catch((err) => console.error("[audit] failed to record", type, (err as Error).message));
  queues.set(instanceId, run);
  void run.finally(() => queues.get(instanceId) === run && queues.delete(instanceId));
  return run;
}

export type AuditQuery = { limit?: number; before?: string; type?: string; target?: string };

/** Newest first. `before` is the `nextCursor` of the previous page (an event ID). */
export async function listAudit(instanceId: string, q: AuditQuery = {}) {
  const limit = Math.min(Math.max(q.limit ?? 50, 1), 200);
  const t = schema.auditEvents;
  const conds = [eq(t.instanceId, instanceId)];
  if (q.type) conds.push(eq(t.type, q.type));
  if (q.target) conds.push(eq(t.targetId, q.target));
  // Compared in SQL (not via a JS Date) so microsecond timestamps can't skip or repeat rows.
  // A cursor from another instance matches no row, so the comparison is NULL and returns nothing.
  if (q.before)
    conds.push(sql`(${t.createdAt}, ${t.id}) < (select c.created_at, c.id from audit_events c where c.id = ${q.before} and c.instance_id = ${instanceId})`);
  const rows = await db().select().from(t).where(and(...conds)).orderBy(desc(t.createdAt), desc(t.id)).limit(limit + 1);
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
      return { id: r.id, type: r.type, actor: { type: r.actorType, id: r.actorId }, target: r.targetId, data, createdAt: r.createdAt };
    }),
    nextCursor: rows.length > limit ? page[page.length - 1].id : null,
  };
}

/**
 * Retention. Removes the oldest entries and remembers where the chain was cut (`purged_seq` and its
 * hash) so verification of what remains still has an anchor.
 */
export async function purgeAudit(retentionDays = RETENTION_DAYS, onlyInstanceId?: string) {
  const cutoff = new Date(Date.now() - retentionDays * 86_400_000);
  const t = schema.auditEvents;
  const old = await db().selectDistinct({ instanceId: t.instanceId }).from(t).where(onlyInstanceId ? and(lt(t.createdAt, cutoff), eq(t.instanceId, onlyInstanceId)) : lt(t.createdAt, cutoff));
  for (const { instanceId } of old) {
    await db().transaction(async (tx) => {
      const [head] = await tx.select().from(schema.auditChains).where(eq(schema.auditChains.instanceId, instanceId)).for("update");
      if (head) {
        const [last] = await tx.select({ seq: t.seq, hash: t.hash }).from(t).where(and(eq(t.instanceId, instanceId), lt(t.createdAt, cutoff), sql`${t.seq} is not null`)).orderBy(desc(t.seq)).limit(1);
        if (last) {
          // Everything up to the newest old entry goes, so what remains is a contiguous run of the chain.
          await tx.update(schema.auditChains).set({ purgedSeq: last.seq!, purgedHash: last.hash!, updatedAt: new Date() }).where(eq(schema.auditChains.instanceId, instanceId));
          await tx.delete(t).where(and(eq(t.instanceId, instanceId), lte(t.seq, last.seq!)));
        }
      }
      await tx.delete(t).where(and(eq(t.instanceId, instanceId), lt(t.createdAt, cutoff), sql`${t.seq} is null`));
    });
  }
}

/** For code paths that only know the user ID (2FA, passkeys): finds the instance first. */
export async function recordForUser(userId: string, type: AuditType, e: { actor?: Actor; data?: Record<string, unknown> } = {}) {
  try {
    const [u] = await db().select({ instanceId: schema.users.instanceId }).from(schema.users).where(eq(schema.users.id, userId));
    if (u) await record(u.instanceId, type, { actor: e.actor ?? { type: "user", id: userId }, target: userId, data: e.data });
  } catch (err) {
    console.error("[audit] failed to record", type, (err as Error).message);
  }
}
