// Prints a fresh test instance's publishable key (for the browser walkthroughs).
import { seedInstance } from "../seed";
import { closeDb } from "../../src/lib/db";
import { closeCache } from "../../src/lib/cache";
const s = await seedInstance("Browser walkthrough", []);
console.log("PK=" + s.publishableKey);
await closeDb();
await closeCache();
