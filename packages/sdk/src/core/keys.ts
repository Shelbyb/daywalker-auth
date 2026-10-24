/** Shared helpers for publishable keys and cookie names. Safe in any runtime. */

export type Config = {
  /** Public key for your instance, e.g. pk_test_... */
  publishableKey: string;
  /** Origin of the Daywalker Auth service, e.g. https://users.daywalker.dev */
  frontendApi: string;
  /** Verified custom domain serving your hosted pages, e.g. https://auth.example.com. Hosted links use it instead of `frontendApi` + `pk`. */
  hostedDomain?: string;
  /** This app is a satellite domain: it shares the primary domain's sessions through a redirect handshake. See the satellite domains guide. */
  isSatellite?: boolean;
  /** Origin of the primary domain (required with `isSatellite`), e.g. https://example.com */
  primaryDomain?: string;
  /** This satellite's own origin, when it can't be read from the request (behind a proxy). Defaults to the request origin. */
  domain?: string;
};

/** Decodes the instance ID from a publishable key. Throws on malformed keys. */
export function instanceIdFromKey(publishableKey: string) {
  const m = publishableKey.match(/^pk_(test|live)_([A-Za-z0-9_-]+)$/);
  const decode = (s: string) => {
    const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
    return typeof atob === "function" ? atob(b64.padEnd(b64.length + ((4 - (b64.length % 4)) % 4), "=")) : Buffer.from(s, "base64url").toString();
  };
  const id = m ? decode(m[2]) : "";
  if (!/^ins_[0-9a-z]{22}$/.test(id)) throw new Error("Invalid publishable key");
  return id;
}

export const normalizeOrigin = (url: string) => new URL(url).origin;
export const issuerFor = (frontendApi: string, instanceId: string) => `${normalizeOrigin(frontendApi)}/i/${instanceId}`;

/** Cookie on *your app's* domain holding the current short-lived JWT, so servers can read it. */
export const SESSION_COOKIE = "__dw_session";
/** Non-secret flag meaning "a session may exist" — lets the server refresh instead of treating the user as signed out. */
export const ACTIVE_COOKIE = "__dw_active";
