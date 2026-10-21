/**
 * Prints the INDEX_KEY that matches your current MASTER_KEY. Set it in your environment
 * BEFORE rotating MASTER_KEY: nothing changes for the app, but lookups stay valid afterwards.
 */
import { deriveIndexKey } from "../src/lib/crypto";

const master = process.env.MASTER_KEY;
if (!master) {
  console.error("Set MASTER_KEY (your current key) first.");
  process.exit(1);
}
console.log(`INDEX_KEY=${deriveIndexKey(master)}`);
console.error("\nAdd this line to your environment and redeploy. It is a secret: store it like MASTER_KEY.");
