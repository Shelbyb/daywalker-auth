import { sql } from "drizzle-orm";
import { db } from "./db";
import { createCipher, deriveIndexKey } from "./crypto";
import { ENCRYPTED_FIELDS } from "./crypto-fields";

type Cipher = ReturnType<typeof createCipher>;
type Row = Record<string, string | null>;

export type RotationResult = { rewritten: Record<string, number>; total: number; committed: boolean };

class DryRun extends Error {}

/**
 * Re-encrypts every field in ENCRYPTED_FIELDS from `oldKey` to `newKey` in ONE transaction:
 * either everything is rewritten and verified, or nothing changes. Tables are locked against
 * writes for the duration. Lookup indexes are not touched (they use INDEX_KEY, which must stay the same).
 */
export async function rotateMasterKey(opts: { oldMasterKey: string; newMasterKey: string; indexKey: string; dryRun?: boolean; log?: (s: string) => void }): Promise<RotationResult> {
  const log = opts.log ?? (() => {});
  if (opts.oldMasterKey === opts.newMasterKey) throw new Error("The new MASTER_KEY must be different from the old one");
  const oldC: Cipher = createCipher(opts.oldMasterKey, opts.indexKey);
  const newC: Cipher = createCipher(opts.newMasterKey, opts.indexKey);
  const rewritten: Record<string, number> = {};
  let total = 0;

  try {
    await db().transaction(async (tx) => {
      for (const table of [...new Set(ENCRYPTED_FIELDS.map((f) => f.table))])
        await tx.execute(sql`lock table ${sql.identifier(table)} in exclusive mode`);

      // The pinned INDEX_KEY must reproduce the indexes already stored; otherwise lookups would break.
      const [probe] = (await tx.execute(sql`select id, instance_id, email_enc, email_index from email_addresses limit 1`)) as unknown as Row[];
      if (probe) {
        const email = oldC.decrypt(probe.email_enc!, `email_addresses.email:${probe.id}`);
        if (oldC.blindIndex(email, `email:${probe.instance_id}`) !== probe.email_index)
          throw new Error("INDEX_KEY doesn't match the indexes in the database. Set INDEX_KEY to the value from `npm run keys:print-index-key` run with the OLD master key");
      }

      for (const f of ENCRYPTED_FIELDS) {
        const keyCols = f.key.map((k) => sql.identifier(k));
        const rows = (await tx.execute(
          sql`select ${sql.join(keyCols, sql`, `)}, ${sql.identifier(f.column)} as v from ${sql.identifier(f.table)} where ${sql.identifier(f.column)} is not null`,
        )) as unknown as Row[];
        for (const r of rows) {
          const ctx = f.context(r as Record<string, string>);
          const plain = oldC.decrypt(r.v!, ctx);
          const next = newC.encrypt(plain, ctx);
          if (newC.decrypt(next, ctx) !== plain) throw new Error(`Verification failed for ${f.table}.${f.column}`);
          const where = sql.join(f.key.map((k) => sql`${sql.identifier(k)} = ${r[k]}`), sql` and `);
          await tx.execute(sql`update ${sql.identifier(f.table)} set ${sql.identifier(f.column)} = ${next} where ${where}`);
        }
        rewritten[`${f.table}.${f.column}`] = rows.length;
        total += rows.length;
        log(`  ${f.table}.${f.column}: ${rows.length}`);
      }
      if (opts.dryRun) throw new DryRun();
    });
  } catch (e) {
    if (e instanceof DryRun) return { rewritten, total, committed: false };
    throw e;
  }
  return { rewritten, total, committed: true };
}

export { deriveIndexKey };
