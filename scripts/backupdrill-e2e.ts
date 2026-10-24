/**
 * The backup/restore drill (scripts/backup-drill.ts), end to end against throwaway databases: a clean source passes
 * (including MASTER_KEY rotation on the restored copy), and a wrong key or a tampered audit chain is caught.
 * Needs pg_dump/pg_restore on PATH and a Postgres role that can create databases (CI's is a superuser).
 */
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { readdirSync, statSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import postgres from "postgres";
import { deriveIndexKey } from "../src/lib/crypto";

let failures = 0;
const check = (name: string, ok: boolean, detail?: unknown) => {
  console.log(`${ok ? "✓" : "✗"} ${name}${ok ? "" : ` — ${JSON.stringify(detail)}`}`);
  if (!ok) failures++;
};

const mainUrl = new URL(process.env.DATABASE_URL!);
const srcName = `drillsrc_${Date.now()}`;
const admin = postgres(mainUrl.toString(), { max: 1, onnotice: () => {} });
const urlFor = (db: string) => { const u = new URL(mainUrl); u.pathname = `/${db}`; return u.toString(); };
const key = randomBytes(48).toString("base64");
const indexKey = deriveIndexKey(key);
const base = { PATH: process.env.PATH, HOME: process.env.HOME, VALKEY_URL: "redis://localhost:6379/7", MAIL_TRANSPORT: "dev" };
const run = (file: string, env: Record<string, string | undefined>, ...args: string[]) => {
  const r = spawnSync("npx", ["tsx", file, ...args], { env: { ...base, ...env } as unknown as NodeJS.ProcessEnv, encoding: "utf8", maxBuffer: 1 << 26 });
  return { code: r.status ?? 1, out: `${r.stdout}${r.stderr}` };
};
const drill = (env: Record<string, string | undefined>) => run("scripts/backup-drill.ts", { SOURCE_DATABASE_URL: urlFor(srcName), DRILL_ADMIN_URL: mainUrl.toString(), MASTER_KEY: key, INDEX_KEY: indexKey, ...env });
const scratchDbs = async () => (await admin`select datname from pg_database where datname like 'drill\\_%' and datname not like 'drillsrc\\_%'`).map((r) => r.datname as string);
const dumpDirs = () => readdirSync(tmpdir()).filter((n) => n.startsWith("dw-drill-"));

await admin.unsafe(`create database ${srcName}`);
const src = postgres(urlFor(srcName), { max: 1, onnotice: () => {} });
try {
  const env = { DATABASE_URL: urlFor(srcName), MASTER_KEY: key, INDEX_KEY: indexKey };
  run("scripts/migrate.ts", env);
  check("fixture data written to the source", run("scripts/masterkey-fixture.ts", env, "populate").code === 0);
  const fingerprint = async () => (await src`select (select md5(string_agg(u::text, '' order by id)) from users u) as users, (select md5(string_agg(a::text, '' order by id)) from audit_events a) as audit, (select count(*)::int from sessions) as sessions`)[0];
  const before = await fingerprint();
  const leftoverBefore = (await scratchDbs()).length;
  const dirsBefore = dumpDirs().length;

  // ---------- Happy path ----------
  const ok = drill({});
  check("drill passes on a good backup", ok.code === 0 && /Drill passed/.test(ok.out), ok.out.slice(-600));
  for (const s of ["pg_dump of a consistent snapshot", "restore into a scratch database", "row counts match the snapshot", "every encrypted field decrypts with the current MASTER_KEY", "email lookups (blind indexes) match INDEX_KEY", "audit hash chains verify for every instance", "MASTER_KEY rotation runs on the restored copy", "after rotation every field decrypts with the NEW key", "after rotation email lookups and audit chains still verify", "after rotation the OLD key no longer decrypts"])
    check(`step reported: ${s}`, ok.out.includes(`PASS  ${s}`), ok.out.slice(-300));
  const n = ok.out.match(/(\d+) encrypted values, (\d+) email indexes, (\d+) audit chains/);
  check("it really checked data: encrypted values, email indexes and at least one audit chain", !!n && Number(n[1]) >= 12 && Number(n[2]) >= 1 && Number(n[3]) >= 1, n?.[0]);
  check("scratch database dropped afterwards", (await scratchDbs()).length === leftoverBefore, await scratchDbs());
  check("dump directory deleted afterwards", dumpDirs().length === dirsBefore, dumpDirs());
  check("the source was not modified (users, audit log, sessions identical)", JSON.stringify(await fingerprint()) === JSON.stringify(before));
  check("no key or connection password appears in the output", !ok.out.includes(key) && !ok.out.includes(indexKey) && !(mainUrl.password && ok.out.includes(mainUrl.password) && mainUrl.password.length > 6));

  // ---------- Wrong MASTER_KEY: the backup can't be read ----------
  const wrong = drill({ MASTER_KEY: randomBytes(48).toString("base64"), INDEX_KEY: undefined });
  check("a wrong MASTER_KEY fails the drill", wrong.code === 1 && /FAIL  every encrypted field decrypts/.test(wrong.out), wrong.out.slice(-400));
  check("and still cleans up", (await scratchDbs()).length === leftoverBefore && dumpDirs().length === dirsBefore);

  // ---------- Wrong INDEX_KEY: lookups would break ----------
  const wrongIdx = drill({ INDEX_KEY: randomBytes(32).toString("base64"), DRILL_SKIP_ROTATION: "1" });
  check("a wrong INDEX_KEY fails the email-lookup check", wrongIdx.code === 1 && /FAIL  email lookups/.test(wrongIdx.out), wrongIdx.out.slice(-300));

  // ---------- Kept artifacts are private ----------
  const kept = drill({ DRILL_KEEP: "1", DRILL_SKIP_ROTATION: "1" });
  const keptDump = kept.out.match(/dump (\S+\.dump)/)?.[1];
  const keptDb = kept.out.match(/database "(drill_[a-z0-9_]+)"/)?.[1];
  check("DRILL_KEEP keeps the scratch database and dump", kept.code === 0 && !!keptDump && !!keptDb && existsSync(keptDump), kept.out.slice(-300));
  if (keptDump) {
    check("the kept dump is mode 0600 inside a 0700 directory", (statSync(keptDump).mode & 0o777) === 0o600 && (statSync(path.dirname(keptDump)).mode & 0o777) === 0o700);
    spawnSync("rm", ["-rf", path.dirname(keptDump)]);
  }
  if (keptDb) await admin.unsafe(`drop database if exists ${keptDb} with (force)`);

  // ---------- Tampered audit log in the source ----------
  const [victim] = await src`select id from audit_events where seq is not null order by seq limit 1`;
  await src`update audit_events set actor_id = 'someone_else' where id = ${victim.id}`;
  const tampered = drill({ DRILL_SKIP_ROTATION: "1" });
  check("a tampered audit log fails the drill", tampered.code === 1 && /FAIL  audit hash chains verify/.test(tampered.out) && /hash_mismatch/.test(tampered.out), tampered.out.slice(-400));
  check("the earlier checks still passed in that run (the failure is specific)", /PASS  every encrypted field decrypts/.test(tampered.out));

  // ---------- Safety ----------
  const noKey = run("scripts/backup-drill.ts", { SOURCE_DATABASE_URL: urlFor(srcName) });
  check("refuses to run without MASTER_KEY", noKey.code === 1 && /MASTER_KEY/.test(noKey.out));
  const noSrc = run("scripts/backup-drill.ts", { MASTER_KEY: key });
  check("refuses to run without a source database", noSrc.code === 1 && /SOURCE_DATABASE_URL/.test(noSrc.out));
  const verifyOnMain = run("scripts/backup-drill-verify.ts", { DATABASE_URL: mainUrl.toString(), MASTER_KEY: key, DRILL_EXPECT_DB: "drill_not_this_one" });
  check("the verifier refuses to run against a database it wasn't told to expect", verifyOnMain.code === 2 && /Refusing/.test(verifyOnMain.out));

} finally {
  await src.end();
  await admin.unsafe(`drop database if exists ${srcName} with (force)`);
  await admin.end();
}
console.log(failures ? `\n${failures} check(s) failed` : "\nAll backup drill checks passed");
process.exit(failures ? 1 : 0);
