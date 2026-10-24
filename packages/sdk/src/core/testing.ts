/**
 * Helpers for end-to-end tests against a DEVELOPMENT instance with test mode on (Dashboard -> Environments, or
 * `backend().testMode.set(true)`). Test addresses and numbers accept the fixed code and nothing is sent to them.
 * Production instances refuse them.
 */

/** The code every test address and test phone number accepts. */
export const TEST_CODE = "424242";
/** Add this to the local part of an email address: `alice+daywalker_test@example.com`. */
export const TEST_EMAIL_TAG = "+daywalker_test";

/** `testEmail("alice")` -> `alice+daywalker_test@example.com`. Add a suffix to get distinct accounts per run: `testEmail("alice", { unique: true })`. */
export function testEmail(name = "user", opts: { domain?: string; unique?: boolean } = {}) {
  const local = opts.unique ? `${name}.${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}` : name;
  return `${local}${TEST_EMAIL_TAG}@${opts.domain ?? "example.com"}`;
}

/** Is this one of the reserved test email addresses? */
export const isTestEmail = (email: string) => /\+daywalker_test(\+|$)/.test((email.trim().toLowerCase().split("@")[0] ?? ""));

/** `testPhone(7)` -> `+15555550107`. The reserved range is +1 555 555 0100 to +1 555 555 0199 (index 0 to 99). */
export function testPhone(index = 0) {
  if (!Number.isInteger(index) || index < 0 || index > 99) throw new Error("testPhone index must be 0 to 99");
  return `+155555501${String(index).padStart(2, "0")}`;
}

/** Is this one of the reserved test phone numbers? */
export const isTestPhone = (phone: string) => /^\+155555501\d{2}$/.test(phone.replace(/[\s().-]/g, ""));
