/**
 * Verification half of the backup/restore drill (see scripts/backup-drill.ts and platform-docs/pages/backup-restore.md).
 * Runs against the database in DATABASE_URL, which the drill points at the RESTORED SCRATCH copy, with the keys in
 * MASTER_KEY / INDEX_KEY. Read-only. Prints one JSON line (counts and row IDs only, never plaintext) and exits
 * non-zero if anything fails.
 *
 * Refuses to run unless DRILL_EXPECT_DB names the database it is connected to, so it can't be pointed at the wrong one by accident.
 */
import { sql } from "drizzle-orm";
import { db, closeDb } from "../src/lib/db";
import { createCipher, deriveIndexKey } from "../src/lib/crypto";
import { ENCRYPTED_FIELDS } from "../src/lib/crypto-fields";
import { verifyChain } from "../src/lib/audit-chain";

type Row = Record<string, string | null>;
const BATCH = 1000;

const { MASTER_KEY, INDEX_KEY, DRILL_EXPECT_DB } = process.env;
if (!MASTER_KEY || !DRILL_EXPECT_DB) {
  console.error("MASTER_KEY and DRILL_EXPECT_DB are required");
  process.exit(2);
}
const [{ name }] = (await db().execute(sql`select current_database() as name`)) as unknown as { name: string }[];
if (name !== DRILL_EXPECT_DB) {
  console.error(`Connected to "${name}", expected "${DRILL_EXPECT_DB}". Refusing to run.`);
  process.exit(2);
}

const cipher = createCipher(MASTER_KEY, INDEX_KEY || deriveIndexKey(MASTER_KEY));
const sample = Number(process.env.DRILL_SAMPLE_PER_COLUMN || 0); // 0 = every row

// ---- 1. Every encrypted field decrypts under the key (AES-GCM also proves it wasn't altered or moved) ----
const fields: Record<string, { checked: number; failed: number; failedIds: string[] }> = {};
for (const f of ENCRYPTED_FIELDS) {
  const label = `${f.table}.${f.column}`;
  const out = (fields[label] = { checked: 0, failed: 0, failedIds: [] as string[] });
  const keyCols = f.key.map((k) => sql.identifier(k));
  for (let offset = 0; ; offset += BATCH) {
    const rows = (await db().execute(
      sql`select ${sql.join(keyCols, sql`, `)}, ${sql.identifier(f.column)} as v from ${sql.identifier(f.table)} where ${sql.identifier(f.column)} is not null order by ${sql.join(keyCols, sql`, `)} limit ${sample ? Math.min(BATCH, sample - offset) : BATCH} offset ${offset}`,
    )) as unknown as Row[];
    if (!rows.length) break;
    for (const r of rows) {
      out.checked++;
      try {
        cipher.decrypt(r.v!, f.context(r as Record<string, string>));
      } catch {
        out.failed++;
        if (out.failedIds.length < 5) out.failedIds.push(f.key.map((k) => r[k]).join("/"));
      }
    }
    if (sample && offset + rows.length >= sample) break;
  }
}

// ---- 2. Email lookups: the stored blind indexes match what this INDEX_KEY computes (sign-in finds the user) ----
const emailIdx = { checked: 0, failed: 0, failedIds: [] as string[] };
for (let offset = 0; ; offset += BATCH) {
  const rows = (await db().execute(sql`select id, instance_id, email_enc, email_index from email_addresses order by id limit ${BATCH} offset ${offset}`)) as unknown as Row[];
  if (!rows.length) break;
  for (const r of rows) {
    emailIdx.checked++;
    let ok = false;
    try {
      ok = cipher.blindIndex(cipher.decrypt(r.email_enc!, `email_addresses.email:${r.id}`), `email:${r.instance_id}`) === r.email_index;
    } catch { /* counted as failed */ }
    if (!ok) { emailIdx.failed++; if (emailIdx.failedIds.length < 5) emailIdx.failedIds.push(r.id!); }
  }
  if (sample && offset + rows.length >= sample) break;
}

// ---- 3. Audit hash chains verify end to end for every instance (uses the app's own verifier, with the keys in the environment) ----
const chains: { checked: number; ok: number; failed: number; failures: { instanceId: string; reason: string; seq: number }[] } = { checked: 0, ok: 0, failed: 0, failures: [] };
const instances = (await db().execute(sql`select instance_id from audit_chains order by instance_id`)) as unknown as { instance_id: string }[];
for (const { instance_id } of instances) {
  chains.checked++;
  const r = await verifyChain(instance_id);
  if (r.ok) chains.ok++;
  else { chains.failed++; chains.failures.push({ instanceId: instance_id, reason: r.problem?.reason ?? "unknown", seq: r.problem?.seq ?? -1 }); }
}

const failed = Object.values(fields).reduce((n, f) => n + f.failed, 0) + emailIdx.failed + chains.failed;
const total = Object.values(fields).reduce((n, f) => n + f.checked, 0);
console.log(JSON.stringify({ ok: failed === 0 && total > 0, database: name, fieldsChecked: total, fields, emailIndexes: emailIdx, auditChains: chains }));
await closeDb();
process.exit(failed === 0 ? 0 : 1);
