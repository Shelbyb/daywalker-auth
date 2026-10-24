/**
 * Satellite domains and the session sync handshake.
 *
 * An application can run on several domains. The primary domain is declared on the instance; satellite domains are
 * other origins the developer proves they control (DNS TXT `daywalker-verify=<token>` at `_daywalker.<host>`; a
 * development instance may use localhost without proof). Primary and verified satellite origins join the instance's
 * origin allow-list (CORS, CSRF check, redirect targets) automatically.
 *
 * The handshake lets a satellite learn about the session on the auth service without third-party cookies:
 *   1. The satellite makes a PKCE-style secret (`verifier`, kept in an httpOnly cookie on the satellite) and sends the
 *      browser on a top-level redirect to GET /v1/client/satellite/sync with `challenge = base64url(sha256(verifier))`.
 *   2. The service reads its own (first-party) refresh cookie, mints a 60 s token for that satellite (`azp`), stores it
 *      encrypted under a random single-use code (60 s) bound to the satellite origin and the challenge, and redirects
 *      back to the satellite's fixed handshake path with only the code in the URL.
 *   3. The satellite's server POSTs the code and verifier to /v1/client/satellite/exchange and gets the token. A code
 *      seen in a URL or log is useless without the verifier, and works once.
 */
import { createHash } from "node:crypto";
import { and, count, desc, eq, isNotNull } from "drizzle-orm";
import { z } from "zod";
import { db, schema } from "../db";
import { cache, rateLimit } from "../cache";
import { decrypt, encrypt } from "../crypto";
import { env } from "../env";
import { ApiError, errors } from "../http";
import { newId, newToken, safeEqual, sha256 } from "../ids";
import { record, type Actor } from "../audit";
import { invalidateInstance } from "./instance";
import { issueToken } from "./sessions";
import { txtRecords } from "./org-domains";
import type { Instance } from "../db/schema";

export const MAX_SATELLITES = 10;
export const HANDSHAKE_PATH = "/__daywalker/handshake";
const CODE_TTL = 60;

const HOST = /^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const isLocalHost = (h: string) => h === "localhost" || h === "127.0.0.1";

/**
 * Turns "example.org", "https://example.org/" or (development only) "localhost:3002" into an origin.
 * https is required except for localhost on a development instance.
 */
export function normalizeOrigin(raw: string, inst: Pick<Instance, "environment">) {
  let u: URL;
  try {
    u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(raw.trim()) ? raw.trim() : `https://${raw.trim()}`);
  } catch {
    throw errors.badRequest("invalid_domain", "Enter a domain like example.org");
  }
  if (u.username || u.password || (u.pathname !== "/" && u.pathname !== "") || u.search || u.hash) throw errors.badRequest("invalid_domain", "Give just the domain, without a path");
  const local = isLocalHost(u.hostname);
  if (local) {
    if (inst.environment !== "development") throw errors.badRequest("domain_not_allowed", "localhost is only allowed on a development instance");
    if (u.protocol !== "http:" && u.protocol !== "https:") throw errors.badRequest("invalid_domain", "Use http or https");
  } else {
    if (u.protocol !== "https:") throw errors.badRequest("invalid_domain", "Satellite domains must use https");
    if (!HOST.test(u.hostname)) throw errors.badRequest("invalid_domain", "Enter a domain like example.org");
  }
  const own = new URL(env().APP_URL);
  if (u.origin === own.origin || (!local && u.hostname === own.hostname)) throw errors.badRequest("domain_not_allowed", "That is the auth service's own domain");
  return { origin: u.origin, hostname: u.hostname, local };
}

type Row = typeof schema.satelliteDomains.$inferSelect;
const view = (d: Row) => ({
  id: d.id,
  origin: d.origin,
  hostname: d.hostname,
  verified: !!d.verifiedAt,
  verifiedAt: d.verifiedAt,
  createdAt: d.createdAt,
  ...(d.verifiedAt ? {} : { dns: { type: "TXT", name: `_daywalker.${d.hostname}`, value: `daywalker-verify=${d.verifyToken}` } }),
});

export async function listSatellites(instanceId: string) {
  const rows = await db().select().from(schema.satelliteDomains).where(eq(schema.satelliteDomains.instanceId, instanceId)).orderBy(desc(schema.satelliteDomains.createdAt));
  return rows.map(view);
}

async function find(instanceId: string, id: string) {
  const [d] = await db().select().from(schema.satelliteDomains).where(and(eq(schema.satelliteDomains.id, id), eq(schema.satelliteDomains.instanceId, instanceId)));
  if (!d) throw errors.notFound("Satellite domain not found");
  return d;
}

export async function addSatellite(inst: Instance, rawOrigin: string, actor: Actor) {
  const { origin, hostname, local } = normalizeOrigin(z.string().max(300).parse(rawOrigin), inst);
  if (origin === inst.settings.primaryDomain) throw errors.badRequest("domain_is_primary", "That is the primary domain");
  const [{ n }] = await db().select({ n: count() }).from(schema.satelliteDomains).where(eq(schema.satelliteDomains.instanceId, inst.id));
  if (n >= MAX_SATELLITES) throw errors.limitReached(`Up to ${MAX_SATELLITES} satellite domains`);
  const [dupe] = await db().select({ id: schema.satelliteDomains.id }).from(schema.satelliteDomains).where(and(eq(schema.satelliteDomains.instanceId, inst.id), eq(schema.satelliteDomains.origin, origin)));
  if (dupe) throw errors.conflict("domain_exists", "That domain is already added");
  const [row] = await db().insert(schema.satelliteDomains).values({ id: newId("sat"), instanceId: inst.id, origin, hostname, verifyToken: newToken(24), verifiedAt: local ? new Date() : null }).returning();
  await invalidateInstance(inst.id);
  void record(inst.id, "satellite_domain.added", { actor, target: row.id, data: { origin } });
  return view(row);
}

export async function verifySatellite(inst: Instance, id: string, actor: Actor) {
  const d = await find(inst.id, id);
  if (d.verifiedAt) return view(d);
  if ((await rateLimit(`${inst.id}:sat_verify`, 20, 3600)) < 0) throw errors.tooMany();
  const found = (await txtRecords(`_daywalker.${d.hostname}`)).includes(`daywalker-verify=${d.verifyToken}`);
  if (!found) throw errors.badRequest("verification_failed", "We couldn't find the TXT record yet. DNS changes can take a while to spread.");
  let row: Row;
  try {
    [row] = await db().update(schema.satelliteDomains).set({ verifiedAt: new Date() }).where(eq(schema.satelliteDomains.id, d.id)).returning();
  } catch (e) {
    if (((e as { cause?: { code?: string } }).cause?.code ?? (e as { code?: string }).code) === "23505") throw errors.conflict("domain_taken", "That domain is already verified by another application");
    throw e;
  }
  await invalidateInstance(inst.id);
  void record(inst.id, "satellite_domain.verified", { actor, target: d.id, data: { origin: d.origin } });
  return view(row);
}

export async function removeSatellite(inst: Instance, id: string, actor: Actor) {
  const d = await find(inst.id, id);
  await db().delete(schema.satelliteDomains).where(eq(schema.satelliteDomains.id, d.id));
  await invalidateInstance(inst.id);
  void record(inst.id, "satellite_domain.removed", { actor, target: d.id, data: { origin: d.origin } });
  return { id, deleted: true as const };
}

export const primaryDomainOf = (inst: Pick<Instance, "settings">) => inst.settings.primaryDomain ?? null;

/** Sets or clears the primary domain (an origin). It becomes an allowed origin; it needs no proof, like any allowed origin. */
export async function setPrimaryDomain(cached: Instance, raw: string | null, actor: Actor) {
  const origin = raw === null || raw === "" ? null : normalizeOrigin(z.string().max(300).parse(raw), cached).origin;
  if (origin) {
    const [sat] = await db().select({ id: schema.satelliteDomains.id }).from(schema.satelliteDomains).where(and(eq(schema.satelliteDomains.instanceId, cached.id), eq(schema.satelliteDomains.origin, origin)));
    if (sat) throw errors.badRequest("domain_is_satellite", "That domain is already a satellite");
  }
  // Read the row, not the cached instance: writing a cached object back would undo other settings changes.
  const [inst] = await db().select().from(schema.instances).where(eq(schema.instances.id, cached.id));
  await db().update(schema.instances).set({ settings: { ...inst.settings, primaryDomain: origin }, updatedAt: new Date() }).where(eq(schema.instances.id, inst.id));
  await invalidateInstance(inst.id);
  void record(inst.id, "instance.primary_domain_updated", { actor, data: { primaryDomain: origin } });
  return { primaryDomain: origin };
}

/** Verified satellite origins of an instance (used to widen the origin allow-list). */
export async function verifiedSatelliteOrigins(instanceId: string) {
  const rows = await db().select({ o: schema.satelliteDomains.origin }).from(schema.satelliteDomains).where(and(eq(schema.satelliteDomains.instanceId, instanceId), isNotNull(schema.satelliteDomains.verifiedAt)));
  return rows.map((r) => r.o);
}

// ---------- Handshake ----------

const b64urlSha256 = (v: string) => createHash("sha256").update(v).digest("base64url");
const codeKey = (code: string) => `sat:code:${sha256(code)}`;
const CHALLENGE = /^[A-Za-z0-9_-]{43}$/;

/** Is `origin` a verified satellite of this instance? */
export async function isVerifiedSatellite(instanceId: string, origin: string) {
  const [d] = await db().select({ id: schema.satelliteDomains.id }).from(schema.satelliteDomains).where(and(eq(schema.satelliteDomains.instanceId, instanceId), eq(schema.satelliteDomains.origin, origin), isNotNull(schema.satelliteDomains.verifiedAt)));
  return !!d;
}

/**
 * Step 2 (the service side of the redirect). Returns the URL to send the browser to: the satellite's handshake path
 * with a one-time `code`, or `status=signed_out` when there is no usable session. Throws (a JSON error, no redirect)
 * when the satellite itself isn't trusted, because redirecting to an untrusted origin would be an open redirect.
 */
export async function startSync(inst: Instance, refreshToken: string | undefined, q: { returnOrigin: string | null; to: string | null; challenge: string | null; primary: string | null }, ip: string) {
  let origin: string;
  try {
    origin = new URL(q.returnOrigin ?? "").origin;
  } catch {
    throw errors.badRequest("invalid_satellite", "Missing or invalid return origin");
  }
  if (!(await isVerifiedSatellite(inst.id, origin))) throw errors.forbidden("That origin isn't a verified satellite of this app").withCode("invalid_satellite");
  const primary = primaryDomainOf(inst);
  if (primary && q.primary && q.primary !== primary) throw errors.badRequest("primary_mismatch", "primaryDomain doesn't match the one set for this app");
  if (!q.challenge || !CHALLENGE.test(q.challenge)) throw errors.badRequest("invalid_challenge", "Missing or invalid challenge");
  if ((await rateLimit(`${inst.id}:sat_sync:${ip}`, 60, 60)) < 0) throw errors.tooMany();

  const back = new URL(HANDSHAKE_PATH, origin); // fixed path: nothing user-supplied decides where the code goes
  if (q.to && q.to.length <= 2048) back.searchParams.set("to", q.to);
  let jwt: string | null = null;
  let reason: string | null = null;
  if (!refreshToken) reason = "no_session";
  else {
    try {
      jwt = (await issueToken(inst, refreshToken, origin)).jwt;
    } catch (e) {
      // Sessions that can't be shared (device-bound, impersonated sessions, 2FA setup pending, ended) look signed out to the satellite.
      if (!(e instanceof ApiError) && !(e instanceof Error && (e as { code?: string }).code)) throw e;
      reason = (e as { code?: string }).code ?? "unavailable";
    }
  }
  if (!jwt) {
    back.searchParams.set("status", "signed_out");
    return back.toString();
  }
  const code = newToken(32);
  await cache().set(codeKey(code), JSON.stringify({ instanceId: inst.id, origin, challenge: q.challenge, jwtEnc: encrypt(jwt, `satellite_code:${sha256(code)}`) }), "EX", CODE_TTL);
  back.searchParams.set("code", code);
  void reason;
  return back.toString();
}

/** Step 3: the satellite's server trades code + verifier for the token. Single use. */
export async function exchangeCode(inst: Instance, input: { code: string; verifier: string }, ip: string) {
  if ((await rateLimit(`${inst.id}:sat_exchange:${ip}`, 60, 60)) < 0) throw errors.tooMany();
  const fail = () => errors.badRequest("invalid_code", "The code is invalid or has expired");
  if (input.code.length > 200 || input.verifier.length < 32 || input.verifier.length > 200) throw fail();
  const raw = await cache().getdel(codeKey(input.code)); // burn it whatever happens next
  if (!raw) throw fail();
  const v = JSON.parse(raw) as { instanceId: string; origin: string; challenge: string; jwtEnc: string };
  if (v.instanceId !== inst.id || !safeEqual(b64urlSha256(input.verifier), v.challenge)) throw fail();
  if (!(await isVerifiedSatellite(inst.id, v.origin))) throw fail(); // removed since the redirect
  return { jwt: decrypt(v.jwtEnc, `satellite_code:${sha256(input.code)}`), origin: v.origin };
}
