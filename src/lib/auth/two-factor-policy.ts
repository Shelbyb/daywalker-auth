/**
 * Required two-factor. When an app (or an organization) requires it, a person without two-factor
 * can still sign in, but gets no session token, so they can't reach the app's backend, until they
 * turn it on. The session itself stays, so the account page can enroll them.
 * - App-wide: after the grace period. Sessions that came through company SSO are exempt (the
 *   identity provider is in charge of MFA there).
 * - Per organization: no grace; without two-factor the token simply carries no org claims, and the
 *   organization can't be made active.
 */
import { eq } from "drizzle-orm";
import { db, schema } from "../db";
import { cache } from "../cache";
import { ApiError } from "../http";
import { hasTwoFactor } from "./mfa";
import type { Instance } from "../db/schema";

export const setupRequiredError = () =>
  new ApiError(403, "two_factor_setup_required", "This app requires two-step verification. Set it up on your account page to continue");

export const inGrace = (inst: Instance) => !!inst.settings.twoFactorGraceUntil && Date.parse(inst.settings.twoFactorGraceUntil) > Date.now();

/** True when this session may not get a token until the person turns on two-factor. */
export async function appRequiresSetup(inst: Instance, userId: string, sessionId: string) {
  if (inst.settings.requireTwoFactor !== true || inGrace(inst)) return false;
  const [sso] = await db().select({ id: schema.samlSessions.sessionId }).from(schema.samlSessions).where(eq(schema.samlSessions.sessionId, sessionId));
  if (sso) return false;
  return !(await hasTwoFactor(userId));
}

const orgKey = (orgId: string) => `org2fa:${orgId}`;
export async function orgRequiresTwoFactor(orgId: string) {
  const hit = await cache().get(orgKey(orgId));
  if (hit !== null) return hit === "1";
  const [o] = await db().select({ r: schema.organizations.requireTwoFactor }).from(schema.organizations).where(eq(schema.organizations.id, orgId));
  await cache().set(orgKey(orgId), o?.r ? "1" : "0", "EX", 60);
  return !!o?.r;
}
export const forgetOrgPolicy = (orgId: string) => cache().del(orgKey(orgId));

/** May this person use this organization right now? */
export async function orgAllowed(orgId: string, userId: string) {
  return !(await orgRequiresTwoFactor(orgId)) || (await hasTwoFactor(userId));
}
