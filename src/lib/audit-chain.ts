/**
 * Tamper-evident audit log. Every entry of an instance is chained to the one before it:
 *
 *   hash = SHA-256(["dw-audit-v1", instanceId, seq, prevHash, id, type, actorType, actorId, targetId, createdAt, dataDigest])
 *
 * `dataDigest` is a keyed HMAC (INDEX_KEY) of the plaintext details, so the chain commits to the
 * details without a database dump becoming a way to test guesses at them, and verification works
 * after MASTER_KEY rotation (details are re-encrypted, not changed). Editing, removing, reordering
 * or inserting an entry breaks the links after it; cutting off the newest entries no longer matches
 * the chain head. The head and the entries retention has removed (`purged_*`) are anchors held in
 * `audit_chains`; for protection against someone who can rewrite the whole database, export the log
 * (or push it to your own bucket) and keep the head hash elsewhere.
 */
import { createHash } from "node:crypto";
import { and, asc, eq, gt, isNull, lte, sql } from "drizzle-orm";
import { db, schema } from "./db";
import { blindIndex, decrypt } from "./crypto";

export const GENESIS_HASH = "0".repeat(64);
export const auditDataContext = (id: string) => `audit_events.data:${id}`;

export type ChainFields = {
  instanceId: string;
  seq: number;
  prevHash: string;
  id: string;
  type: string;
  actorType: string;
  actorId: string | null;
  targetId: string | null;
  createdAt: Date | string;
  dataDigest: string;
};

/** Keyed commitment to the plaintext details ("" when there are none). */
export const dataDigestOf = (instanceId: string, plaintext: string | null) => (plaintext === null ? "" : blindIndex(plaintext, `audit-data:${instanceId}`));

export function entryHash(f: ChainFields) {
  const at = typeof f.createdAt === "string" ? f.createdAt : f.createdAt.toISOString();
  return createHash("sha256")
    .update(JSON.stringify(["dw-audit-v1", f.instanceId, f.seq, f.prevHash, f.id, f.type, f.actorType, f.actorId ?? null, f.targetId ?? null, at, f.dataDigest]))
    .digest("hex");
}

export type ChainProblem = {
  seq: number;
  id: string | null;
  reason: "missing_entry" | "prev_hash_mismatch" | "hash_mismatch" | "data_modified" | "data_removed" | "undecryptable" | "truncated" | "head_mismatch" | "unchained_entries";
  message: string;
};

const MESSAGE: Record<ChainProblem["reason"], string> = {
  missing_entry: "An entry is missing from the sequence",
  prev_hash_mismatch: "An entry doesn't follow from the one before it",
  hash_mismatch: "An entry's contents don't match its hash",
  data_modified: "An entry's details were changed",
  data_removed: "An entry's details were removed",
  undecryptable: "An entry's details can't be decrypted",
  truncated: "The newest entries are missing",
  head_mismatch: "The log doesn't end where the chain head says it should",
  unchained_entries: "Entries exist that were never added to the chain",
};
const problem = (reason: ChainProblem["reason"], seq: number, id: string | null = null): ChainProblem => ({ seq, id, reason, message: MESSAGE[reason] });

export type VerifyResult = {
  /** True when every chained entry checks out. */
  ok: boolean;
  /** False when this instance has no chained entries yet. */
  chained: boolean;
  /** Entries checked. */
  checked: number;
  firstSeq: number | null;
  lastSeq: number | null;
  /** Where the chain ends now: keep this somewhere safe to detect later truncation or rewrites. */
  head: { seq: number; hash: string } | null;
  /** The chain began recording at this time; older entries have no hash. */
  startedAt: string | null;
  /** Retention has removed entries up to here. */
  purged: { seq: number; hash: string } | null;
  problem?: ChainProblem;
};

const BATCH = 500;

/** Recomputes the whole chain from the stored entries. O(entries); retention keeps that to 90 days. */
export async function verifyChain(instanceId: string): Promise<VerifyResult> {
  const [head] = await db().select().from(schema.auditChains).where(eq(schema.auditChains.instanceId, instanceId));
  if (!head) return { ok: true, chained: false, checked: 0, firstSeq: null, lastSeq: null, head: null, startedAt: null, purged: null };
  const base = { chained: true, head: { seq: head.seq, hash: head.hash }, startedAt: head.startedAt.toISOString(), purged: head.purgedSeq ? { seq: head.purgedSeq, hash: head.purgedHash } : null };
  const t = schema.auditEvents;
  let prev = head.purgedHash;
  let expected = head.purgedSeq + 1;
  let checked = 0;
  let firstSeq: number | null = null;
  const fail = (p: ChainProblem): VerifyResult => ({ ...base, ok: false, checked, firstSeq, lastSeq: expected > head.purgedSeq + 1 ? expected - 1 : null, problem: p });

  for (let cursor = head.purgedSeq; ; ) {
    const rows = await db().select().from(t).where(and(eq(t.instanceId, instanceId), gt(t.seq, cursor), lte(t.seq, head.seq))).orderBy(asc(t.seq)).limit(BATCH); // entries appended meanwhile are beyond the head we read
    if (!rows.length) break;
    for (const r of rows) {
      const seq = r.seq!;
      if (seq !== expected) return fail(problem("missing_entry", expected));
      if (r.prevHash !== prev) return fail(problem("prev_hash_mismatch", seq, r.id));
      let digest = r.dataDigest ?? "";
      if (!r.dataErased) {
        // The stored digest must match the details as they are now.
        let plaintext: string | null = null;
        if (r.dataEnc) {
          try {
            plaintext = decrypt(r.dataEnc, auditDataContext(r.id));
          } catch {
            return fail(problem("undecryptable", seq, r.id));
          }
        }
        const now = dataDigestOf(instanceId, plaintext);
        if (now !== digest) return fail(problem(plaintext === null ? "data_removed" : "data_modified", seq, r.id));
        digest = now;
      }
      const h = entryHash({ instanceId, seq, prevHash: r.prevHash!, id: r.id, type: r.type, actorType: r.actorType, actorId: r.actorId, targetId: r.targetId, createdAt: r.createdAt, dataDigest: digest });
      if (h !== r.hash) return fail(problem("hash_mismatch", seq, r.id));
      firstSeq ??= seq;
      prev = h;
      expected = seq + 1;
      checked++;
    }
    cursor = rows[rows.length - 1].seq!;
  }
  if (expected - 1 !== head.seq) return fail(problem("truncated", expected));
  if (prev !== head.hash) return fail(problem("head_mismatch", head.seq));
  // Rows past the head are legitimate only if the head has since moved on (an append raced with this check).
  const [{ max }] = await db().select({ max: sql<number | null>`max(${t.seq})` }).from(t).where(eq(t.instanceId, instanceId));
  if (max !== null && max > head.seq) {
    const [now] = await db().select({ seq: schema.auditChains.seq }).from(schema.auditChains).where(eq(schema.auditChains.instanceId, instanceId));
    if (!now || max > now.seq) return fail(problem("head_mismatch", max));
  }
  // Entries recorded after the chain began must be in it.
  const [{ n }] = await db().select({ n: sql<number>`count(*)::int` }).from(t).where(and(eq(t.instanceId, instanceId), isNull(t.seq), sql`${t.createdAt} >= ${new Date(head.startedAt).toISOString()}::timestamptz`));
  if (n > 0) return fail(problem("unchained_entries", head.seq));
  return { ...base, ok: true, checked, firstSeq, lastSeq: checked ? expected - 1 : null };
}

// ---------- Export (NDJSON) ----------

export type ExportOptions = { from?: Date; to?: Date; /** Only chained entries after this sequence number (used by the bucket push). */ afterSeq?: number; /** At most this many entries. */ limit?: number };

/**
 * One JSON object per line: a header, the entries (oldest first, details decrypted), a footer with the
 * chain head. Each entry carries `prevHash`, `hash` and `dataDigest`, so `verifyAuditExport` in the server
 * SDK can check the links without any key.
 */
export async function* exportLines(instanceId: string, o: ExportOptions = {}): AsyncGenerator<string> {
  const t = schema.auditEvents;
  const [head] = await db().select().from(schema.auditChains).where(eq(schema.auditChains.instanceId, instanceId));
  yield JSON.stringify({
    type: "daywalker.audit.header",
    version: 1,
    instanceId,
    exportedAt: new Date().toISOString(),
    chain: head ? { startedAt: head.startedAt.toISOString(), purgedSeq: head.purgedSeq, purgedHash: head.purgedHash } : null,
  });
  let count = 0;
  let lastSeq: number | null = null;
  let lastHash: string | null = null;
  const conds = [eq(t.instanceId, instanceId)];
  if (o.from) conds.push(sql`${t.createdAt} >= ${o.from.toISOString()}::timestamptz`);
  if (o.to) conds.push(sql`${t.createdAt} <= ${o.to.toISOString()}::timestamptz`);
  if (o.afterSeq !== undefined) conds.push(gt(t.seq, o.afterSeq));
  // Entries from before chaining first (by time), then the chain by sequence.
  const phases = o.afterSeq !== undefined ? [false] : [true, false];
  for (const legacy of phases) {
    let after: { at: Date; id: string } | number = legacy ? { at: new Date(0), id: "" } : (o.afterSeq ?? 0);
    for (;;) {
      if (o.limit !== undefined && count >= o.limit) break;
      const where = legacy
        ? and(...conds, isNull(t.seq), sql`(${t.createdAt}, ${t.id}) > (${(after as { at: Date }).at.toISOString()}::timestamptz, ${(after as { id: string }).id})`)
        : and(...conds, gt(t.seq, after as number));
      const rows = await db().select().from(t).where(where).orderBy(...(legacy ? [asc(t.createdAt), asc(t.id)] : [asc(t.seq)])).limit(Math.min(BATCH, o.limit === undefined ? BATCH : o.limit - count));
      if (!rows.length) break;
      for (const r of rows) {
        let data: unknown = null;
        if (r.dataEnc) {
          try {
            data = JSON.parse(decrypt(r.dataEnc, auditDataContext(r.id)));
          } catch {
            data = null;
          }
        }
        yield JSON.stringify({
          type: "event",
          seq: r.seq,
          id: r.id,
          event: r.type,
          actor: { type: r.actorType, id: r.actorId },
          target: r.targetId,
          data,
          dataErased: r.dataErased,
          createdAt: r.createdAt.toISOString(),
          prevHash: r.prevHash,
          hash: r.hash,
          dataDigest: r.dataDigest,
        });
        count++;
        if (r.seq !== null) { lastSeq = r.seq; lastHash = r.hash; }
      }
      const last = rows[rows.length - 1];
      after = legacy ? { at: last.createdAt, id: last.id } : last.seq!;
      if (rows.length < BATCH) break;
    }
  }
  yield JSON.stringify({ type: "daywalker.audit.footer", count, lastSeq, lastHash, head: head ? { seq: head.seq, hash: head.hash } : null });
}

/** Marks entries as erased when their details are removed (account deletion), keeping the digest so the chain still verifies. */
export async function eraseDetailsFor(instanceId: string, userId: string) {
  const t = schema.auditEvents;
  await db().update(t).set({ dataEnc: null, dataErased: true }).where(and(eq(t.instanceId, instanceId), sql`(${t.targetId} = ${userId} or ${t.actorId} = ${userId})`, sql`${t.dataEnc} is not null`));
}

