import { drizzle, type PostgresJsDatabase } from "drizzle-orm/postgres-js";
import postgres from "postgres";
import * as schema from "./schema";
import { env } from "../env";

type DB = PostgresJsDatabase<typeof schema>;
const g = globalThis as unknown as { __db?: DB; __pg?: ReturnType<typeof postgres> };

/** Lazily connected so builds don't require a database. Reused across dev hot reloads. */
export function db(): DB {
  if (!g.__db) {
    g.__pg = postgres(env().DATABASE_URL, { max: 10 });
    g.__db = drizzle({ client: g.__pg, schema });
  }
  return g.__db;
}

export async function closeDb() {
  await g.__pg?.end();
  g.__db = undefined;
  g.__pg = undefined;
}

export { schema };
