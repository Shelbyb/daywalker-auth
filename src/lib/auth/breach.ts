/**
 * Rejects passwords that appear in known data breaches, using the Pwned Passwords range API
 * (k-anonymity): only the first 5 hex characters of the password's SHA-1 leave this server,
 * and responses are padded so their size doesn't hint at the prefix either. The full hash and
 * the password itself are never sent or stored.
 *
 * Fails open: if the API is slow or down, the password is accepted (and a warning is logged),
 * so an outage elsewhere never stops people signing up.
 */
import { createHash } from "node:crypto";
import { env } from "../env";
import { errors } from "../http";
import type { Instance } from "../db/schema";

const TIMEOUT_MS = 2500;

export const breachCheckEnabled = (inst: Instance) => inst.settings.breachedPasswordCheck !== false;

/** Tests point this at a local mock; never allowed on an HTTPS deployment. */
function apiBase() {
  const t = process.env.PWNED_PASSWORDS_TEST_URL;
  if (t) {
    if (env().APP_URL.startsWith("https://")) throw new Error("PWNED_PASSWORDS_TEST_URL is not allowed on an HTTPS deployment");
    return t.replace(/\/$/, "");
  }
  return "https://api.pwnedpasswords.com";
}

/** How many times the password appears in breach data; 0 if never, null if the check couldn't run. */
export async function breachCount(password: string): Promise<number | null> {
  const sha1 = createHash("sha1").update(password, "utf8").digest("hex").toUpperCase();
  const prefix = sha1.slice(0, 5), suffix = sha1.slice(5);
  try {
    const res = await fetch(`${apiBase()}/range/${prefix}`, {
      headers: { "Add-Padding": "true", "user-agent": "daywalker-auth" },
      signal: AbortSignal.timeout(TIMEOUT_MS),
      redirect: "error",
      cache: "no-store",
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    for (const line of (await res.text()).split("\n")) {
      const [s, n] = line.trim().split(":");
      if (s === suffix) return Number(n) || 0; // padding rows have a count of 0
    }
    return 0;
  } catch (e) {
    console.warn("[breach] check skipped:", (e as Error).message);
    return null;
  }
}

export async function assertNotBreached(inst: Instance, password: string) {
  if (!breachCheckEnabled(inst)) return;
  if (((await breachCount(password)) ?? 0) > 0)
    throw errors.badRequest(
      "password_breached",
      "This password has appeared in a data breach, so it isn't safe to use. Please choose a different one",
    );
}
