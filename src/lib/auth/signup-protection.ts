/**
 * Bot and abuse protection for new accounts.
 *
 * - Email rules (per instance): only allowed domains, never blocked domains, and optionally no
 *   throwaway (disposable) providers. Applied to every self-service way of creating an account:
 *   password sign-up and social sign-in. Not to SSO or SCIM (the company vouches for those).
 * - Cloudflare Turnstile (optional): a human check on password sign-up and on emailing sign-in
 *   codes, verified server-side. Fails closed: if the check can't be verified, the request is refused.
 *
 * Refusals use one generic message, so the rules themselves aren't revealed to a prober.
 */
import { createRequire } from "node:module";
import { decrypt, encrypt } from "../crypto";
import { env } from "../env";
import { ApiError, errors } from "../http";
import { guardedFetch } from "../net-guard";
import type { Instance } from "../db/schema";

const domainOf = (email: string) => email.trim().toLowerCase().split("@")[1] ?? "";
/** `sub.example.com` matches a rule for `example.com`. */
const matches = (domain: string, rule: string) => domain === rule || domain.endsWith(`.${rule}`);

let disposable: Set<string> | null = null;
function isDisposable(domain: string) {
  disposable ??= new Set(createRequire(import.meta.url)("disposable-email-domains") as string[]);
  // Check the domain and each parent (mail.throwaway.example → throwaway.example).
  const parts = domain.split(".");
  for (let i = 0; i < parts.length - 1; i++) if (disposable.has(parts.slice(i).join("."))) return true;
  return false;
}

export const notAllowedError = () => new ApiError(403, "sign_up_not_allowed", "Sign-ups with this email address aren't allowed for this app");

/** Throws `sign_up_not_allowed` if a NEW account with this email breaks the instance's rules. */
export function assertEmailAllowed(inst: Instance, email: string | null | undefined) {
  const s = inst.settings;
  const domain = email ? domainOf(email) : "";
  const allowed = s.signUpAllowedDomains ?? [];
  if (allowed.length && (!domain || !allowed.some((r) => matches(domain, r)))) throw notAllowedError();
  if (!domain) return;
  if ((s.signUpBlockedDomains ?? []).some((r) => matches(domain, r))) throw notAllowedError();
  if (s.blockDisposableEmails && isDisposable(domain)) throw notAllowedError();
}

// ---------- Turnstile ----------

const captchaCtx = (instanceId: string) => `instances.captcha_secret:${instanceId}`;
export const encryptCaptchaSecret = (instanceId: string, secret: string) => encrypt(secret, captchaCtx(instanceId));

/** What the browser needs to show the widget (null when the human check is off). */
export const captchaInfo = (inst: Instance) => (inst.settings.captchaSiteKey && inst.captchaSecretEnc ? { provider: "turnstile" as const, siteKey: inst.settings.captchaSiteKey } : null);

/** Tests point this at a local mock; never allowed on an HTTPS deployment. */
function base() {
  const t = process.env.TURNSTILE_TEST_BASE_URL;
  if (t) {
    if (env().APP_URL.startsWith("https://")) throw new Error("TURNSTILE_TEST_BASE_URL is not allowed on an HTTPS deployment");
    return t.replace(/\/$/, "");
  }
  return "https://challenges.cloudflare.com";
}

/** Throws unless the instance has no human check, or `token` is a fresh, valid Turnstile answer. */
export async function assertHuman(inst: Instance, token: string | null | undefined, ip: string | null) {
  if (!captchaInfo(inst)) return;
  if (!token || token.length > 2048) throw errors.badRequest("captcha_required", "Please complete the check that you're not a robot");
  const form = new URLSearchParams({ secret: decrypt(inst.captchaSecretEnc!, captchaCtx(inst.id)), response: token, ...(ip ? { remoteip: ip } : {}) });
  let ok = false;
  try {
    const r = await guardedFetch(`${base()}/turnstile/v0/siteverify`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
      body: form.toString(),
      timeoutMs: 5000,
      maxBytes: 16_384,
    });
    const body = JSON.parse(r.text) as { success?: boolean };
    ok = r.status === 200 && body.success === true;
  } catch {
    ok = false; // fail closed
  }
  if (!ok) throw errors.badRequest("captcha_failed", "We couldn't confirm you're not a robot. Please try again");
}
