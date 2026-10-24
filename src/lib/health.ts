/**
 * Service health for the public /status page and GET /v1/health. Deliberately coarse: each component is
 * "ok", "degraded" or "down", nothing else. No versions, hostnames, counts, latencies, error text, instance
 * IDs or configuration values, so an unauthenticated visitor learns only whether things work.
 */
import { eq, sql } from "drizzle-orm";
import { db, schema } from "./db";
import { cache } from "./cache";
import { decrypt } from "./crypto";
import { env } from "./env";
import { effectiveSettings } from "./platform-settings";

export type Level = "ok" | "degraded" | "down";
export type Component = "database" | "valkey" | "email" | "jobs" | "signingKeys";
export type Health = { status: Level; components: Record<Component, Level>; checkedAt: string };

export const COMPONENT_LABELS: Record<Component, string> = {
  database: "Database",
  valkey: "Cache and rate limits",
  email: "Email delivery",
  jobs: "Background jobs (webhooks, cleanup)",
  signingKeys: "Token signing",
};

const CHECK_TIMEOUT_MS = 2_000;
const MEMO_MS = 5_000;
const HEARTBEAT_KEY = "health:jobs:heartbeat";
const HEARTBEAT_TTL_S = 120;
/** A heartbeat older than this means the job loop has stalled (it beats every 15 s). */
const HEARTBEAT_MAX_AGE_MS = 90_000;

/** Called by the job runner after each successful tick (see src/instrumentation.ts). Never throws. */
export async function recordJobHeartbeat() {
  try {
    await cache().set(HEARTBEAT_KEY, String(Date.now()), "EX", HEARTBEAT_TTL_S);
  } catch {
    // if Valkey is down the health check says so itself
  }
}

const withTimeout = <T>(p: Promise<T>) =>
  Promise.race([p, new Promise<never>((_, rej) => setTimeout(() => rej(new Error("timeout")), CHECK_TIMEOUT_MS).unref())]);

const attempt = async (fn: () => Promise<Level>): Promise<Level> => {
  try {
    return await withTimeout(fn());
  } catch {
    return "down";
  }
};

async function checkDatabase(): Promise<Level> {
  await db().execute(sql`select 1`);
  return "ok";
}

async function checkValkey(): Promise<Level> {
  return (await cache().ping()) === "PONG" ? "ok" : "down";
}

/**
 * Email is usable if a transport is configured: a Resend key (env or saved platform setting). The "dev" transport only
 * logs, so it counts as ok solely where insecure transport is explicitly allowed (local development and the test suites);
 * env validation already refuses it in production.
 */
async function checkEmail(): Promise<Level> {
  if (env().MAIL_TRANSPORT !== "resend") return process.env.NODE_ENV !== "production" || process.env.ALLOW_INSECURE_TRANSPORT === "1" ? "ok" : "degraded";
  return (await effectiveSettings()).resendApiKey ? "ok" : "degraded";
}

/** The job runner beats in Valkey every tick. Missing or stale = jobs aren't running anywhere. */
async function checkJobs(): Promise<Level> {
  const beat = await cache().get(HEARTBEAT_KEY);
  if (!beat) return "degraded";
  return Date.now() - Number(beat) <= HEARTBEAT_MAX_AGE_MS ? "ok" : "degraded";
}

/**
 * There is an active signing key AND it decrypts with the current MASTER_KEY (a wrong or rotated-away
 * master key would make every sign-in fail while the database looks fine). Nothing about the key is returned.
 */
async function checkSigningKeys(): Promise<Level> {
  const [row] = await db().select({ id: schema.signingKeys.id, enc: schema.signingKeys.privateKeyEnc }).from(schema.signingKeys).where(eq(schema.signingKeys.active, true)).limit(1);
  if (!row) return "degraded"; // fresh install: no instance exists yet
  try {
    decrypt(row.enc, `signing_keys.private:${row.id}`);
    return "ok";
  } catch {
    return "down";
  }
}

async function compute(): Promise<Health> {
  const [database, valkey, email, jobs, signingKeys] = await Promise.all([
    attempt(checkDatabase),
    attempt(checkValkey),
    attempt(checkEmail),
    attempt(checkJobs),
    attempt(checkSigningKeys),
  ]);
  const components = { database, valkey, email, jobs, signingKeys };
  // Without the database, the cache or token signing the service can't serve sign-ins at all; the rest degrades it.
  const status: Level = database === "down" || valkey === "down" || signingKeys === "down" ? "down" : Object.values(components).some((l) => l !== "ok") ? "degraded" : "ok";
  return { status, components, checkedAt: new Date().toISOString() };
}

let memo: { at: number; value: Promise<Health> } | undefined;
/** Shared for a few seconds so a burst of unauthenticated requests costs one round of checks, not one each. */
export function getHealth(): Promise<Health> {
  if (memo && Date.now() - memo.at < MEMO_MS) return memo.value;
  const value = compute();
  memo = { at: Date.now(), value };
  return value;
}
