/**
 * Backup/restore drill. Proves a database backup is actually usable, not just that a file exists:
 *
 *   1. pg_dump the source at one consistent snapshot (read-only; the source is never written to).
 *   2. Restore into a brand-new scratch database (drill_<random>).
 *   3. Row counts per table match the snapshot.
 *   4. Every encrypted field decrypts with MASTER_KEY, email blind indexes match INDEX_KEY, every audit hash chain verifies.
 *   5. Rotate MASTER_KEY inside the scratch copy only (the real `npm run keys:rotate-master`), then repeat 4 with the
 *      NEW key and check the old key no longer decrypts. This proves the restored data survives a rotation.
 *   6. Drop the scratch database and delete the dump.
 *
 *   MASTER_KEY=... [INDEX_KEY=...] SOURCE_DATABASE_URL=postgres://... npm run drill:backup
 *
 * Environment:
 *   SOURCE_DATABASE_URL   database to back up (default DATABASE_URL). Only ever read.
 *   DRILL_ADMIN_URL       a server connection that may CREATE DATABASE, where the scratch copy lives
 *                         (default: the source's server). Prefer a throwaway server you control, not production's cluster.
 *   MASTER_KEY, INDEX_KEY the keys the backup was made under (INDEX_KEY defaults to the one MASTER_KEY implies)
 *   DATABASE_CA_CERT      PEM, for verified TLS to the source (same as the app)
 *   DRILL_KEEP=1          keep the scratch database and the dump afterwards (the paths are printed; delete them yourself)
 *   DRILL_SKIP_ROTATION=1 skip step 5
 *   DRILL_SAMPLE_PER_COLUMN=N  check only the first N rows of each encrypted column (default: all)
 *
 * The dump holds encrypted personal data and password hashes: it is written to a private (0700) temp directory
 * and deleted at the end. Keys are passed to child processes through their environment, never on a command line.
 */
import { execFileSync, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import postgres from "postgres";
import { deriveIndexKey, MASTER_KEY_BYTES } from "../src/lib/crypto";

const log = (s = "") => console.log(s);
const fail = (s: string): never => { throw new Error(s); };
const t0 = Date.now();

const sourceUrl = process.env.SOURCE_DATABASE_URL || process.env.DATABASE_URL;
const masterKey = process.env.MASTER_KEY;
if (!sourceUrl) fail("Set SOURCE_DATABASE_URL (or DATABASE_URL).");
if (!masterKey) fail("Set MASTER_KEY to the key the backup was made under.");
const indexKey = process.env.INDEX_KEY || deriveIndexKey(masterKey!);
const adminUrl = process.env.DRILL_ADMIN_URL || sourceUrl!;
const caCert = process.env.DATABASE_CA_CERT?.replace(/\\n/g, "\n");
const keep = process.env.DRILL_KEEP === "1";

const src = new URL(sourceUrl!);
const adm = new URL(adminUrl);
const sourceDb = decodeURIComponent(src.pathname.slice(1));
if (!sourceDb) fail("The source URL has no database name.");
const scratchDb = `drill_${Date.now().toString(36)}_${randomBytes(4).toString("hex")}`;
if (!/^drill_[a-z0-9_]+$/.test(scratchDb) || scratchDb === sourceDb) fail("Refusing: bad scratch database name");

const dir = mkdtempSync(path.join(tmpdir(), "dw-drill-")); // mode 0700
const dumpFile = path.join(dir, "backup.dump");
let certFile: string | undefined;
if (caCert) { certFile = path.join(dir, "ca.pem"); writeFileSync(certFile, caCert, { mode: 0o600 }); }

/** libpq environment for a URL, so passwords never appear in a process list. */
type Env = Record<string, string | undefined>;
const asEnv = (e: Env) => e as unknown as NodeJS.ProcessEnv;
const pgEnv = (u: URL, database: string): Env => ({
  PATH: process.env.PATH,
  HOME: process.env.HOME,
  PGHOST: u.hostname, PGPORT: u.port || "5432", PGUSER: decodeURIComponent(u.username), PGPASSWORD: decodeURIComponent(u.password), PGDATABASE: database,
  ...(u.searchParams.get("sslmode") ? { PGSSLMODE: u.searchParams.get("sslmode")! } : {}),
  ...(certFile ? { PGSSLROOTCERT: certFile } : {}),
});
const urlFor = (u: URL, database: string) => { const c = new URL(u); c.pathname = `/${encodeURIComponent(database)}`; return c.toString(); };
const client = (url: string, max = 2) => postgres(url, { max, onnotice: () => {}, ...(caCert ? { ssl: { ca: caCert, rejectUnauthorized: true } } : {}) });
const tool = (cmd: string, args: string[], env: Env) => {
  try { execFileSync(cmd, args, { env: asEnv(env), stdio: ["ignore", "pipe", "pipe"], maxBuffer: 1 << 26 }); }
  catch (e) { fail(`${cmd} failed: ${String((e as { stderr?: Buffer }).stderr ?? e).trim().split("\n").slice(-5).join("\n")}`); }
};
const results: { step: string; ok: boolean; note?: string }[] = [];
const step = (name: string, ok: boolean, note?: string) => { results.push({ step: name, ok, note }); log(`${ok ? "PASS" : "FAIL"}  ${name}${note ? `  (${note})` : ""}`); if (!ok) throw new Error(`Drill failed at: ${name}`); };

const adminDb = adm.pathname.slice(1) ? decodeURIComponent(adm.pathname.slice(1)) : "postgres";
let admin: ReturnType<typeof postgres> | undefined;
let created = false;

try {
  // ---------- preflight ----------
  for (const t of ["pg_dump", "pg_restore"]) {
    const r = spawnSync(t, ["--version"], { encoding: "utf8" });
    if (r.status !== 0) fail(`${t} not found. Install the PostgreSQL client tools (same major version as the server or newer).`);
  }
  log(`Source: ${src.hostname}/${sourceDb}   Scratch: ${adm.hostname}/${scratchDb}\n`);

  // ---------- 1. consistent snapshot + dump ----------
  const source = client(sourceUrl!, 1);
  const counts: Record<string, number> = {};
  let sourceTables: string[] = [];
  await source.begin("isolation level repeatable read read only", async (tx) => {
    const [{ snap }] = await tx`select pg_export_snapshot() as snap`;
    sourceTables = (await tx`select table_schema || '.' || table_name as t from information_schema.tables where table_type = 'BASE TABLE' and table_schema in ('public', 'drizzle') order by 1`).map((r) => r.t as string);
    for (const t of sourceTables) {
      const [schemaName, table] = t.split(".");
      counts[t] = Number((await tx`select count(*)::bigint as n from ${tx(schemaName)}.${tx(table)}`)[0].n);
    }
    // pg_dump joins the exported snapshot, so the dump and the counts describe exactly the same moment.
    tool("pg_dump", ["--format=custom", "--no-owner", "--no-privileges", `--snapshot=${snap}`, "--file", dumpFile], pgEnv(src, sourceDb));
  });
  await source.end();
  chmodSync(dumpFile, 0o600);
  step("pg_dump of a consistent snapshot", true, `${sourceTables.length} tables, ${Object.values(counts).reduce((a, b) => a + b, 0)} rows`);

  // ---------- 2. restore into a scratch database ----------
  admin = client(urlFor(adm, adminDb), 1);
  await admin.unsafe(`create database "${scratchDb}"`);
  created = true;
  tool("pg_restore", ["--no-owner", "--no-privileges", "--exit-on-error", "--dbname", scratchDb, dumpFile], pgEnv(adm, scratchDb));
  step("restore into a scratch database", true);

  // ---------- 3. row counts ----------
  const scratchUrl = urlFor(adm, scratchDb);
  const scratch = client(scratchUrl, 1);
  const [{ cur }] = await scratch`select current_database() as cur`;
  if (cur !== scratchDb) fail(`Connected to "${cur}", not the scratch database. Stopping before anything is changed.`);
  const mismatched: string[] = [];
  for (const t of sourceTables) {
    const [schemaName, table] = t.split(".");
    const n = Number((await scratch`select count(*)::bigint as n from ${scratch(schemaName)}.${scratch(table)}`)[0].n);
    if (n !== counts[t]) mismatched.push(`${t}: ${counts[t]} -> ${n}`);
  }
  await scratch.end();
  step("row counts match the snapshot in every table", mismatched.length === 0, mismatched.slice(0, 5).join("; ") || `${sourceTables.length} tables`);

  // ---------- 4. verify with the current keys ----------
  const verify = (master: string, label: string) => {
    const r = spawnSync("npx", ["tsx", path.join(import.meta.dirname, "backup-drill-verify.ts")], {
      env: asEnv({ PATH: process.env.PATH, HOME: process.env.HOME, DATABASE_URL: scratchUrl, ...(caCert ? { DATABASE_CA_CERT: caCert } : {}), MASTER_KEY: master, INDEX_KEY: indexKey, DRILL_EXPECT_DB: scratchDb, ...(process.env.DRILL_SAMPLE_PER_COLUMN ? { DRILL_SAMPLE_PER_COLUMN: process.env.DRILL_SAMPLE_PER_COLUMN } : {}) }),
      encoding: "utf8", maxBuffer: 1 << 26,
    });
    const line = r.stdout.trim().split("\n").pop() ?? "";
    let out: { ok: boolean; fieldsChecked: number; fields: Record<string, { failed: number; failedIds: string[] }>; emailIndexes: { checked: number; failed: number }; auditChains: { checked: number; ok: number; failed: number; failures: unknown[] } } | undefined;
    try { out = JSON.parse(line); } catch { /* handled below */ }
    if (!out) fail(`${label}: the verifier produced no result (${r.stderr.trim().split("\n").slice(-3).join(" | ")})`);
    return { out: out!, status: r.status };
  };
  const describe = (o: ReturnType<typeof verify>["out"]) => {
    const bad = Object.entries(o.fields).filter(([, f]) => f.failed > 0).map(([k, f]) => `${k} (${f.failed}: ${f.failedIds.join(",")})`);
    return { bad, note: `${o.fieldsChecked} encrypted values, ${o.emailIndexes.checked} email indexes, ${o.auditChains.checked} audit chains` };
  };

  const v1 = verify(masterKey!, "current key");
  const d1 = describe(v1.out);
  step("every encrypted field decrypts with the current MASTER_KEY", v1.out.fieldsChecked > 0 && d1.bad.length === 0, d1.bad.slice(0, 5).join("; ") || d1.note);
  step("email lookups (blind indexes) match INDEX_KEY", v1.out.emailIndexes.failed === 0, `${v1.out.emailIndexes.checked} checked`);
  step("audit hash chains verify for every instance", v1.out.auditChains.failed === 0, v1.out.auditChains.failed ? JSON.stringify(v1.out.auditChains.failures).slice(0, 300) : `${v1.out.auditChains.checked} chains`);

  // ---------- 5. rotate MASTER_KEY inside the scratch copy, verify again ----------
  if (process.env.DRILL_SKIP_ROTATION !== "1") {
    const newKey = randomBytes(MASTER_KEY_BYTES).toString("base64");
    const rot = spawnSync("npx", ["tsx", path.join(import.meta.dirname, "rotate-master-key.ts")], {
      env: asEnv({ PATH: process.env.PATH, HOME: process.env.HOME, DATABASE_URL: scratchUrl, ...(caCert ? { DATABASE_CA_CERT: caCert } : {}), OLD_MASTER_KEY: masterKey!, NEW_MASTER_KEY: newKey, INDEX_KEY: indexKey, MASTER_KEY: masterKey! }),
      encoding: "utf8", maxBuffer: 1 << 26,
    });
    step("MASTER_KEY rotation runs on the restored copy", rot.status === 0, rot.status === 0 ? (rot.stdout.match(/Done: (\d+) values/)?.[0] ?? "done") : rot.stderr.trim().split("\n").slice(-2).join(" | "));
    const v2 = verify(newKey, "new key");
    const d2 = describe(v2.out);
    step("after rotation every field decrypts with the NEW key", v2.out.fieldsChecked > 0 && d2.bad.length === 0, d2.bad.slice(0, 5).join("; ") || d2.note);
    step("after rotation email lookups and audit chains still verify", v2.out.emailIndexes.failed === 0 && v2.out.auditChains.failed === 0);
    const v3 = verify(masterKey!, "old key");
    step("after rotation the OLD key no longer decrypts (rotation really re-encrypted)", v3.out.fieldsChecked > 0 && Object.values(v3.out.fields).some((f) => f.failed > 0) && v3.status !== 0);
  }

  log(`\nDrill passed in ${Math.round((Date.now() - t0) / 1000)} s. This is your measured restore time for this database size, plus verification.`);
  process.exitCode = 0;
} catch (e) {
  console.error(`\nDRILL FAILED: ${(e as Error).message}`);
  process.exitCode = 1;
} finally {
  if (keep) {
    log(`\nKept (DRILL_KEEP=1). Delete when done: dump ${dumpFile}${created ? `, database "${scratchDb}" on ${adm.hostname}` : ""}`);
  } else {
    try { if (admin && created) await admin.unsafe(`drop database if exists "${scratchDb}" with (force)`); } catch (e) { console.error(`Could not drop scratch database "${scratchDb}": ${(e as Error).message}. Drop it manually.`); process.exitCode = 1; }
    rmSync(dir, { recursive: true, force: true });
  }
  await admin?.end();
}
