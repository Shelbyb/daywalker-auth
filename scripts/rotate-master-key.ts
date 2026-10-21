/**
 * Re-encrypts all stored data under a new MASTER_KEY. See /docs/guides/rotating-keys.
 *
 *   OLD_MASTER_KEY=... NEW_MASTER_KEY=... INDEX_KEY=... DATABASE_URL=... npm run keys:rotate-master
 *   (add DRY_RUN=1 to check everything and roll back)
 */
import { closeDb } from "../src/lib/db";
import { rotateMasterKey } from "../src/lib/rotate";

const { OLD_MASTER_KEY, NEW_MASTER_KEY, INDEX_KEY, DRY_RUN } = process.env;
if (!OLD_MASTER_KEY || !NEW_MASTER_KEY) {
  console.error("Set OLD_MASTER_KEY and NEW_MASTER_KEY.");
  process.exit(1);
}
if (!INDEX_KEY) {
  console.error("Set INDEX_KEY first (run `npm run keys:print-index-key` with your OLD MASTER_KEY).\nWithout it, lookups by email would stop working after the rotation.");
  process.exit(1);
}
try {
  console.log(DRY_RUN ? "Dry run: nothing will be saved.\n" : "Re-encrypting. Writes to these tables are paused until this finishes.\n");
  const r = await rotateMasterKey({ oldMasterKey: OLD_MASTER_KEY, newMasterKey: NEW_MASTER_KEY, indexKey: INDEX_KEY, dryRun: !!DRY_RUN, log: console.log });
  console.log(r.committed ? `\nDone: ${r.total} values re-encrypted and verified.\nNow set MASTER_KEY to the new key (keep INDEX_KEY) and redeploy.` : `\nDry run OK: ${r.total} values would be re-encrypted. Nothing was changed.`);
} catch (e) {
  console.error(`\nFailed, and nothing was changed: ${(e as Error).message}`);
  process.exitCode = 1;
} finally {
  await closeDb();
}
