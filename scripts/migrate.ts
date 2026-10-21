import { migrate } from "drizzle-orm/postgres-js/migrator";
import { db, closeDb } from "../src/lib/db";

await migrate(db(), { migrationsFolder: "./drizzle" });
console.log("Migrations applied");
await closeDb();
