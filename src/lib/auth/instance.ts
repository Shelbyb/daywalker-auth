import { and, eq, isNull } from "drizzle-orm";
import { db, schema } from "../db";
import { cached, cache } from "../cache";
import { sha256 } from "../ids";
import { errors } from "../http";
import type { Instance } from "../db/schema";

/** Publishable keys are public: they only identify the instance, like a client ID. */
export function publishableKey(inst: Pick<Instance, "id" | "environment">) {
  const env = inst.environment === "production" ? "live" : "test";
  return `pk_${env}_${Buffer.from(inst.id).toString("base64url")}`;
}

export function parsePublishableKey(pk: string | null | undefined) {
  const m = pk?.match(/^pk_(test|live)_([A-Za-z0-9_-]+)$/);
  if (!m) return null;
  const id = Buffer.from(m[2], "base64url").toString("utf8");
  return /^ins_[0-9a-z]{22}$/.test(id) ? id : null;
}

export async function getInstance(id: string): Promise<Instance | null> {
  // Dates come back as strings from the JSON cache; callers only use settings/ids/origins.
  return cached(`ins:${id}`, 300, async () => {
    const [row] = await db().select().from(schema.instances).where(eq(schema.instances.id, id));
    if (!row) return null;
    // The primary domain and verified satellite domains are allowed origins too (CORS, CSRF check, redirect targets).
    // Only this runtime copy is widened; the stored list is what the developer entered.
    const { verifiedSatelliteOrigins } = await import("./satellites");
    const extra = [row.settings.primaryDomain, ...(await verifiedSatelliteOrigins(id))].filter((o): o is string => !!o && !row.allowedOrigins.includes(o));
    return extra.length ? { ...row, allowedOrigins: [...row.allowedOrigins, ...extra] } : row;
  });
}

export const invalidateInstance = (id: string) => cache().del(`ins:${id}`);

/** Frontend API: resolve instance from the publishable key header or query. */
export async function instanceFromPublishableKey(req: Request) {
  const pk = req.headers.get("x-publishable-key") ?? new URL(req.url).searchParams.get("pk");
  const id = parsePublishableKey(pk);
  const inst = id ? await getInstance(id) : null;
  if (!inst) throw errors.unauthorized("Invalid publishable key");
  return inst;
}

/** Backend API: `Authorization: Bearer sk_...`. Only the SHA-256 of the key is stored. */
export async function instanceFromSecretKey(req: Request) {
  const token = req.headers.get("authorization")?.match(/^Bearer (sk_(?:test|live)_[A-Za-z0-9_-]+)$/)?.[1];
  if (!token) throw errors.unauthorized("Missing secret key");
  const h = sha256(token);
  const instanceId = await cached(`sk:${h}`, 60, async () => {
    const [row] = await db()
      .select({ instanceId: schema.apiKeys.instanceId })
      .from(schema.apiKeys)
      .where(and(eq(schema.apiKeys.keyHash, h), isNull(schema.apiKeys.revokedAt)));
    return row?.instanceId ?? null;
  });
  const inst = instanceId ? await getInstance(instanceId) : null;
  if (!inst) throw errors.unauthorized("Invalid secret key");
  return inst;
}
