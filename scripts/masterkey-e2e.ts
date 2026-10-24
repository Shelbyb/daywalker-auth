/**
 * MASTER_KEY rotation, end to end, against a throwaway database. Needs a Postgres role that can
 * create databases (CI's is a superuser; locally: ALTER ROLE auth CREATEDB).
 */
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import postgres from "postgres";
import { getTableColumns, getTableName, is } from "drizzle-orm";
import { PgTable } from "drizzle-orm/pg-core";
import * as schema from "../src/lib/db/schema";
import { ENCRYPTED_FIELDS } from "../src/lib/crypto-fields";
import { deriveIndexKey } from "../src/lib/crypto";

let failures = 0;
const check = (name: string, ok: boolean, detail?: unknown) => {
  console.log(`${ok ? "✓" : "✗"} ${name}${ok ? "" : ` — ${JSON.stringify(detail)}`}`);
  if (!ok) failures++;
};

// ---------- Completeness: no encrypted column can be forgotten ----------
const registered = new Set(ENCRYPTED_FIELDS.map((f) => `${f.table}.${f.column}`));
const missing: string[] = [];
for (const t of Object.values(schema)) {
  if (!is(t, PgTable)) continue;
  for (const c of Object.values(getTableColumns(t))) if (c.name.endsWith("_enc") && !registered.has(`${getTableName(t)}.${c.name}`)) missing.push(`${getTableName(t)}.${c.name}`);
}
check("every *_enc column in the schema is in the rotation registry", missing.length === 0, missing);

// ---------- Throwaway database ----------
const mainUrl = new URL(process.env.DATABASE_URL!);
const dbName = `rot_${Date.now()}`;
const admin = postgres(mainUrl.toString(), { max: 1 });
await admin.unsafe(`create database ${dbName}`);
const url = new URL(mainUrl);
url.pathname = `/${dbName}`;

const oldKey = randomBytes(48).toString("base64"), newKey = randomBytes(48).toString("base64");
const indexKey = deriveIndexKey(oldKey);
const base = { ...process.env, DATABASE_URL: url.toString(), VALKEY_URL: "redis://localhost:6379/7", MAIL_TRANSPORT: "dev" };
const run = (file: string, env: Record<string, string>, ...args: string[]) => {
  try {
    return { code: 0, out: execFileSync("npx", ["tsx", file, ...args], { env: { ...base, ...env } as NodeJS.ProcessEnv, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }) };
  } catch (e) {
    const err = e as { status?: number; stdout?: string; stderr?: string };
    return { code: err.status ?? 1, out: `${err.stdout ?? ""}${err.stderr ?? ""}` };
  }
};
const result = (out: string) => JSON.parse(out.split("\n").find((l) => l.startsWith("RESULT "))!.slice(7));

try {
  run("scripts/migrate.ts", { MASTER_KEY: oldKey });
  check("print-index-key matches the derived index key", run("scripts/print-index-key.ts", { MASTER_KEY: oldKey }).out.includes(`INDEX_KEY=${indexKey}`));

  const populate = run("scripts/masterkey-fixture.ts", { MASTER_KEY: oldKey, INDEX_KEY: indexKey }, "populate");
  check("fixture data written under the old key", populate.code === 0, populate.out.slice(-400));
  const before = result(run("scripts/masterkey-fixture.ts", { MASTER_KEY: oldKey, INDEX_KEY: indexKey }, "verify").out);
  check("everything reads back under the old key", Object.values(before.checks).every(Boolean), before.checks);
  const populated = Object.entries(before.counts as Record<string, number>).filter(([, n]) => n > 0).map(([k]) => k);
  check("the fixture covers most encrypted columns", populated.length >= 12, populated);

  // Guard rails
  check("refuses to run without INDEX_KEY", run("scripts/rotate-master-key.ts", { OLD_MASTER_KEY: oldKey, NEW_MASTER_KEY: newKey }).code === 1);
  check("refuses when old and new keys are the same", run("scripts/rotate-master-key.ts", { OLD_MASTER_KEY: oldKey, NEW_MASTER_KEY: oldKey, INDEX_KEY: indexKey }).code === 1);
  const wrongIdx = run("scripts/rotate-master-key.ts", { OLD_MASTER_KEY: oldKey, NEW_MASTER_KEY: newKey, INDEX_KEY: randomBytes(32).toString("base64") });
  check("refuses a wrong INDEX_KEY (would break lookups) and changes nothing", wrongIdx.code === 1 && /INDEX_KEY/.test(wrongIdx.out));

  const dry = run("scripts/rotate-master-key.ts", { OLD_MASTER_KEY: oldKey, NEW_MASTER_KEY: newKey, INDEX_KEY: indexKey, DRY_RUN: "1" });
  check("dry run succeeds and says nothing was changed", dry.code === 0 && /Nothing was changed/.test(dry.out), dry.out.slice(-300));
  const afterDry = result(run("scripts/masterkey-fixture.ts", { MASTER_KEY: oldKey, INDEX_KEY: indexKey }, "verify").out);
  check("after a dry run the old key still works", Object.values(afterDry.checks).every(Boolean));

  const wrongOld = run("scripts/rotate-master-key.ts", { OLD_MASTER_KEY: randomBytes(48).toString("base64"), NEW_MASTER_KEY: newKey, INDEX_KEY: indexKey });
  check("a wrong old key fails cleanly", wrongOld.code === 1);
  const stillOld = result(run("scripts/masterkey-fixture.ts", { MASTER_KEY: oldKey, INDEX_KEY: indexKey }, "verify").out);
  check("failed attempts leave the data untouched", Object.values(stillOld.checks).every(Boolean));

  // The real thing
  const rot = run("scripts/rotate-master-key.ts", { OLD_MASTER_KEY: oldKey, NEW_MASTER_KEY: newKey, INDEX_KEY: indexKey });
  check("rotation succeeds", rot.code === 0 && /re-encrypted and verified/.test(rot.out), rot.out.slice(-300));
  const after = result(run("scripts/masterkey-fixture.ts", { MASTER_KEY: newKey, INDEX_KEY: indexKey }, "verify").out);
  check("everything reads back under the NEW key (names, email, sign-in, webhooks, signing)", Object.values(after.checks).every(Boolean), after.checks);
  check("same number of values in every column", JSON.stringify(after.counts) === JSON.stringify(before.counts));
  const oldNow = run("scripts/masterkey-fixture.ts", { MASTER_KEY: oldKey, INDEX_KEY: indexKey }, "verify");
  check("the OLD key can no longer decrypt anything", oldNow.code !== 0 || !oldNow.out.includes("RESULT ") || !Object.values(result(oldNow.out).checks).every(Boolean));
  const again = run("scripts/rotate-master-key.ts", { OLD_MASTER_KEY: oldKey, NEW_MASTER_KEY: newKey, INDEX_KEY: indexKey });
  check("running it a second time with the old key fails safely", again.code === 1);
  const stillNew = result(run("scripts/masterkey-fixture.ts", { MASTER_KEY: newKey, INDEX_KEY: indexKey }, "verify").out);
  check("and the data is still intact under the new key", Object.values(stillNew.checks).every(Boolean));
} finally {
  await admin.unsafe(`drop database if exists ${dbName} with (force)`);
  await admin.end();
}
console.log(failures ? `\n${failures} check(s) failed` : "\nAll master key rotation checks passed");
process.exit(failures ? 1 : 0);
