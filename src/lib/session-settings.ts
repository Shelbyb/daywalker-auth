import type { Instance } from "./db/schema";

export type SessionSettings = {
  /** When off, sessions don't expire by age (they still end at the 90-day hard cap). */
  maxLifetimeEnabled: boolean;
  /** End a session after this many idle minutes; null = never. */
  inactivityTimeoutMinutes: number | null;
  /** When off, signing in revokes the user's other sessions in this instance. */
  multiSession: boolean;
  /** Extra token claims: name -> template such as "{{user.email}}". */
  customClaims: Record<string, string>;
};

export const SESSION_SETTINGS_DEFAULTS: SessionSettings = { maxLifetimeEnabled: true, inactivityTimeoutMinutes: null, multiSession: true, customClaims: {} };

export const RESERVED_CLAIMS = ["sub", "iss", "aud", "exp", "nbf", "iat", "jti", "sid", "azp", "org_id", "org_role", "org_permissions"];
export const MAX_CLAIMS = 10;
export const MAX_CLAIMS_BYTES = 1024;
export const HARD_CAP_DAYS = 90;
const NAME = /^[a-zA-Z][a-zA-Z0-9_]{0,39}$/;
const VARS = ["user.id", "user.email", "user.first_name", "user.last_name", "org.id", "org.role"] as const;
const TEMPLATE = /\{\{\s*([a-z_.]+)\s*\}\}/g;

/** Returns an error message, or null when the claims are acceptable. */
export function validateClaims(claims: Record<string, unknown>): string | null {
  const entries = Object.entries(claims);
  if (entries.length > MAX_CLAIMS) return `At most ${MAX_CLAIMS} custom claims`;
  for (const [k, v] of entries) {
    if (!NAME.test(k)) return `Claim name "${k}" must be letters, digits or underscores`;
    if (RESERVED_CLAIMS.includes(k)) return `"${k}" is a reserved claim`;
    if (typeof v !== "string" || v.length > 200) return `Claim "${k}" must be a string of up to 200 characters`;
    for (const m of v.matchAll(TEMPLATE)) if (!(VARS as readonly string[]).includes(m[1])) return `Unknown variable "${m[1]}" in claim "${k}". Use ${VARS.join(", ")}`;
  }
  if (JSON.stringify(claims).length > MAX_CLAIMS_BYTES) return "Custom claims are too large";
  return null;
}

export function sessionSettings(inst: Pick<Instance, "settings">): SessionSettings {
  const s = inst.settings?.sessions ?? {};
  const t = s.inactivityTimeoutMinutes;
  const claims = s.customClaims && typeof s.customClaims === "object" && !validateClaims(s.customClaims) ? s.customClaims : {};
  return {
    maxLifetimeEnabled: typeof s.maxLifetimeEnabled === "boolean" ? s.maxLifetimeEnabled : true,
    inactivityTimeoutMinutes: typeof t === "number" && Number.isInteger(t) && t >= 1 ? t : null,
    multiSession: typeof s.multiSession === "boolean" ? s.multiSession : true,
    customClaims: claims,
  };
}

export const usesUserVars = (claims: Record<string, string>) => Object.values(claims).some((v) => /\{\{\s*user\./.test(v));

/** Fills templates; unknown or missing values become empty strings. */
export function renderClaims(claims: Record<string, string>, ctx: Record<string, string | null | undefined>) {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(claims)) out[k] = v.replace(TEMPLATE, (_m, name: string) => ctx[name] ?? "");
  return out;
}
