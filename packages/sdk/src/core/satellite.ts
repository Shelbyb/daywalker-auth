/** Satellite domains: shared names and helpers for the session sync handshake. Safe in any runtime (browser, Node, edge). */

/** Paths the satellite app serves (the Next.js `authProxy` handles them for you). */
export const SATELLITE_SYNC_PATH = "/__daywalker/sync";
export const SATELLITE_HANDSHAKE_PATH = "/__daywalker/handshake";
/** httpOnly cookie on the satellite holding the secret that proves the same browser finishes the handshake. */
export const SATELLITE_VERIFIER_COOKIE = "__dw_sat_v";
/** Readable flag: the last sync found no session. Stops redirect loops; expires after a minute. */
export const SATELLITE_SIGNED_OUT_COOKIE = "__dw_sat_out";
/** Counts syncs in the last minute so a misconfiguration ends in an error instead of a redirect loop. */
export const SATELLITE_TRY_COOKIE = "__dw_sat_try";

export type SatelliteConfig = { isSatellite?: boolean; /** Origin of the primary domain, e.g. https://example.com */ primaryDomain?: string; /** This satellite's own origin when it can't be read from the request (behind a proxy). */ domain?: string };

/** Throws a clear error for a satellite config that can't work. */
export function assertSatelliteConfig(c: SatelliteConfig) {
  if (!c.isSatellite) return;
  if (!c.primaryDomain) throw new Error("isSatellite needs primaryDomain (the origin of your primary domain)");
  try {
    if (new URL(c.primaryDomain).origin === (c.domain ? new URL(c.domain).origin : null)) throw new Error("same");
  } catch (e) {
    if ((e as Error).message === "same") throw new Error("A satellite can't be its own primary domain");
    throw new Error("primaryDomain must be an origin like https://example.com");
  }
}

const b64url = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

/** A fresh verifier and its challenge (base64url SHA-256). */
export async function createVerifier() {
  const verifier = b64url(crypto.getRandomValues(new Uint8Array(32)));
  const challenge = b64url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))));
  return { verifier, challenge };
}

/** Only same-origin targets: a path on this site, or an absolute URL on its own origin. Anything else becomes "/". */
export function safeReturnTarget(to: string | null | undefined, ownOrigin: string) {
  if (!to || to.length > 2048) return "/";
  if (to.startsWith("/") && !to.startsWith("//") && !to.includes("\\")) return to;
  try {
    const u = new URL(to);
    if (u.origin === ownOrigin) return u.pathname + u.search + u.hash;
  } catch {}
  return "/";
}

/** The service URL that starts the sync (step 1 of the handshake). */
export function buildSyncUrl(cfg: { frontendApi: string; publishableKey: string; primaryDomain?: string }, a: { satelliteOrigin: string; to: string; challenge: string }) {
  const u = new URL("/v1/client/satellite/sync", cfg.frontendApi);
  u.searchParams.set("pk", cfg.publishableKey);
  u.searchParams.set("return", a.satelliteOrigin);
  u.searchParams.set("to", a.to);
  u.searchParams.set("challenge", a.challenge);
  if (cfg.primaryDomain) u.searchParams.set("primary", new URL(cfg.primaryDomain).origin);
  return u.toString();
}
