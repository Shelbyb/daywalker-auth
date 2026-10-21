import { drizzle, type PostgresJsDatabase } from "drizzle-orm/postgres-js";
import postgres from "postgres";
import * as schema from "./schema";
import { env } from "../env";

type DB = PostgresJsDatabase<typeof schema>;
const g = globalThis as unknown as { __db?: DB; __pg?: ReturnType<typeof postgres> };

/** Lazily connected so builds don't require a database. Reused across dev hot reloads. */
export function db(): DB {
  if (!g.__db) {
    const { DATABASE_URL, DATABASE_CA_CERT } = env();
    // With a CA cert, verify the server certificate against it (postgres-js ssl option overrides sslmode in the URL).
    const ssl = DATABASE_CA_CERT ? { ca: DATABASE_CA_CERT.replace(/\\n/g, "\n"), rejectUnauthorized: true } : undefined;
    g.__pg = postgres(DATABASE_URL, { max: 10, ...(ssl ? { ssl } : {}) });
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
