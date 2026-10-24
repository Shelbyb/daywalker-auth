/**
 * The Account Portal's "Unauthorized sign in" page. Only a coarse reason code ever travels in the
 * URL; the page maps it to a fixed message, so nothing from the request is shown and the codes
 * never say whether an account exists (a suspended account is only reported after the person
 * has proved who they are).
 */
export const UNAUTHORIZED_REASONS = {
  sign_up_restricted: { title: "Sign-ups are restricted", body: "This app doesn't accept new accounts with that email address. Contact the app's owner if you think this is a mistake." },
  account_locked: { title: "Your account is locked", body: "This account can't sign in right now. Contact the app's owner for help." },
  origin_not_allowed: { title: "Sign-in isn't allowed from here", body: "This page was opened from a site that isn't allowed to sign in to this app." },
  sso_failed: { title: "Single sign-on failed", body: "Your identity provider didn't let you sign in. Try again, or contact your IT administrator." },
} as const;
export type UnauthorizedReason = keyof typeof UNAUTHORIZED_REASONS;

export const GENERIC_UNAUTHORIZED = { title: "You can't sign in", body: "You aren't allowed to sign in to this app. Contact the app's owner if you think this is a mistake." } as const;

export const unauthorizedMessage = (reason?: string | null) =>
  reason && Object.hasOwn(UNAUTHORIZED_REASONS, reason) ? UNAUTHORIZED_REASONS[reason as UnauthorizedReason] : GENERIC_UNAUTHORIZED;

/**
 * Which API errors are genuine refusals by the instance (as opposed to recoverable mistakes like a
 * wrong password). Everything else returns null and stays on the sign-in/sign-up page.
 */
export function refusalReason(code: string, message?: string): UnauthorizedReason | null {
  if (code === "sign_up_not_allowed") return "sign_up_restricted";
  if (code === "forbidden" && message && /suspended/i.test(message)) return "account_locked";
  if (code === "forbidden" && message && /origin not allowed/i.test(message)) return "origin_not_allowed";
  return null;
}

/** Absolute URL of the page for an instance, keeping the app's (already allow-listed) redirect. */
export function unauthorizedUrl(base: string, pk: string, reason: UnauthorizedReason, redirect?: string | null) {
  const to = new URL(`${base}/unauthorized-sign-in`);
  to.searchParams.set("pk", pk);
  to.searchParams.set("reason", reason);
  if (redirect) to.searchParams.set("redirect_url", redirect);
  return to;
}
