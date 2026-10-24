/**
 * Test mode, for writing end-to-end tests against a DEVELOPMENT instance without a mailbox or a phone.
 *
 * With it on, addresses like `name+daywalker_test@example.com` and the reserved phone numbers +1 555 555 0100 to
 * +1 555 555 0199 accept the fixed code 424242 and no email or text is sent to them. Nothing else changes: real
 * addresses and numbers behave as usual, and the normal attempt limits still apply to the fixed code.
 *
 * It is refused, loudly, wherever it could be abused:
 *  - production instances never honor it: the setting can't be turned on, sign-up with a test address is refused
 *    (`test_mode_unavailable`), and so are test phone numbers (`test_phone_unavailable`);
 *  - the platform's own dashboard instance never honors it;
 *  - config cloning never copies it (it isn't on the allow-list), so dev -> prod can't carry it over;
 *  - a test address never counts as proof of a company domain (organization auto-join and suggestions skip it).
 */
import { ApiError, errors } from "../http";
import { parsePublishableKey } from "./instance";
import type { Instance } from "../db/schema";

export const TEST_CODE = "424242";
export const TEST_EMAIL_TAG = "+daywalker_test";
export const TEST_PHONE_RANGE = "+1 555 555 0100 to +1 555 555 0199";

/** `name+daywalker_test@host`, or the tag followed by another tag (`name+daywalker_test+2@host`). */
export const isTestEmail = (email: string) => /\+daywalker_test(\+|$)/.test((email.trim().toLowerCase().split("@")[0] ?? ""));
/** The reserved fictional range +1 555 555 01XX (spaces and punctuation are ignored). */
export const isTestPhone = (phone: string) => /^\+155555501\d{2}$/.test(phone.replace(/[\s().-]/g, ""));

const isPlatform = (inst: Pick<Instance, "id">) => parsePublishableKey(process.env.PLATFORM_PUBLISHABLE_KEY) === inst.id;

/** Can test mode be used on this instance at all? Development instances only, never the platform's own. */
export const testModeAvailable = (inst: Pick<Instance, "id" | "environment">) => inst.environment === "development" && !isPlatform(inst);
export const testModeActive = (inst: Pick<Instance, "id" | "environment" | "settings">) => testModeAvailable(inst) && inst.settings?.testMode?.enabled === true;

const unavailable = (what: "email" | "phone", inst: Pick<Instance, "environment">) =>
  new ApiError(
    400,
    what === "email" ? "test_mode_unavailable" : "test_phone_unavailable",
    inst.environment === "production"
      ? `Test ${what === "email" ? "addresses (+daywalker_test)" : "phone numbers"} only work on development instances`
      : `Turn on test mode to use test ${what === "email" ? "addresses (+daywalker_test)" : "phone numbers"}`,
  );

/** Production refuses test addresses outright (sign-up, sending codes). Elsewhere a no-op. */
export function assertNoTestEmailOnProduction(inst: Pick<Instance, "environment">, email: string | null | undefined) {
  if (email && inst.environment === "production" && isTestEmail(email)) throw unavailable("email", inst);
}

/**
 * Should this email be treated as a test address (fixed code, nothing sent)? Throws on production for test-looking
 * addresses; on a development instance with test mode off they are ordinary addresses.
 */
export function emailInTestMode(inst: Pick<Instance, "id" | "environment" | "settings">, email: string) {
  if (!isTestEmail(email)) return false;
  assertNoTestEmailOnProduction(inst, email);
  return testModeActive(inst);
}

/** Phone numbers: same idea, but a reserved number is never usable without test mode (there is no real owner to text). */
export function phoneInTestMode(inst: Pick<Instance, "id" | "environment" | "settings">, phone: string) {
  if (!isTestPhone(phone)) return false;
  if (!testModeActive(inst)) throw unavailable("phone", inst);
  return true;
}

/** Sends the mail unless the recipient is a test address in test mode. Returns whether it was sent. */
export async function sendMailUnlessTest(inst: Pick<Instance, "id" | "environment" | "settings">, mail: Parameters<typeof import("../mail").sendMail>[0]) {
  if (emailInTestMode(inst, mail.to)) return false;
  await (await import("../mail")).sendMail(mail);
  return true;
}

export const testModeView = (inst: Pick<Instance, "id" | "environment" | "settings">) => ({
  available: testModeAvailable(inst),
  enabled: testModeActive(inst),
  code: TEST_CODE,
  emailTag: TEST_EMAIL_TAG,
  phoneRange: TEST_PHONE_RANGE,
});

export function assertCanEnableTestMode(inst: Pick<Instance, "id" | "environment">) {
  if (!testModeAvailable(inst)) throw errors.forbidden("Test mode is only available on development instances").withCode("test_mode_unavailable");
}
