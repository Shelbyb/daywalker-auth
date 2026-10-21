import Valkey from "iovalkey";
import { env } from "./env";

const g = globalThis as unknown as { __valkey?: Valkey };

export function cache(): Valkey {
  return (g.__valkey ??= new Valkey(env().VALKEY_URL, { maxRetriesPerRequest: 2, lazyConnect: false }));
}

export async function closeCache() {
  await g.__valkey?.quit();
  g.__valkey = undefined;
}

/** Read-through JSON cache. */
export async function cached<T>(key: string, ttlSeconds: number, load: () => Promise<T>): Promise<T> {
  const hit = await cache().get(key);
  if (hit !== null) return JSON.parse(hit) as T;
  const value = await load();
  if (value !== undefined && value !== null) await cache().set(key, JSON.stringify(value), "EX", ttlSeconds);
  return value;
}

/**
 * Fixed-window rate limiter. Returns remaining attempts, or -1 when the limit is hit.
 * Atomic via MULTI so concurrent requests can't both slip through on the first hit.
 */
export async function rateLimit(key: string, limit: number, windowSeconds: number) {
  const k = `rl:${key}`;
  const [[, count]] = (await cache().multi().incr(k).expire(k, windowSeconds, "NX").exec()) as [[null, number]];
  return count > limit ? -1 : limit - count;
}
