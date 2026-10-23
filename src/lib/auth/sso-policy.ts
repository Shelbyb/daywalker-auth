/**
 * "SSO required": when a connection has it on (and is enabled), people at its email domains can
 * only sign in through the identity provider. Every other way in (password, email code, magic link,
 * passkey, social sign-in, password reset) is refused for those addresses.
 *
 * Kept free of other auth imports so session creation can call it without an import cycle.
 */
import { and, eq } from "drizzle-orm";
import { db, schema } from "../db";
import { decrypt } from "../crypto";
import { ApiError } from "../http";

export const ssoRequiredError = () =>
  new ApiError(403, "sso_required", "Your company requires single sign-on. Choose “Sign in with SSO” instead.");

const domainOf = (email: string) => email.trim().toLowerCase().split("@")[1] ?? "";

/** The cheap common case first: does this app enforce SSO anywhere? */
async function anyEnforced(instanceId: string) {
  const [r] = await db()
    .select({ id: schema.samlConnections.id })
    .from(schema.samlConnections)
    .where(and(eq(schema.samlConnections.instanceId, instanceId), eq(schema.samlConnections.enabled, true), eq(schema.samlConnections.ssoRequired, true)))
    .limit(1);
  return !!r;
}

/** Does an enabled connection that requires SSO own this address's domain? */
export async function ssoRequiredFor(instanceId: string, email: string) {
  const domain = domainOf(email);
  if (!domain || !(await anyEnforced(instanceId))) return false;
  const [r] = await db()
    .select({ id: schema.samlConnections.id })
    .from(schema.samlDomains)
    .innerJoin(schema.samlConnections, eq(schema.samlConnections.id, schema.samlDomains.connectionId))
    .where(and(
      eq(schema.samlDomains.instanceId, instanceId),
      eq(schema.samlDomains.domain, domain),
      eq(schema.samlConnections.enabled, true),
      eq(schema.samlConnections.ssoRequired, true),
    ))
    .limit(1);
  return !!r;
}

export async function assertSsoNotRequired(instanceId: string, email: string) {
  if (await ssoRequiredFor(instanceId, email)) throw ssoRequiredError();
}

/** Same check from a user ID, using their primary email. The backstop for every way of starting a session. */
export async function assertSsoNotRequiredForUser(instanceId: string, userId: string) {
  if (!(await anyEnforced(instanceId))) return;
  const [e] = await db()
    .select({ id: schema.emailAddresses.id, enc: schema.emailAddresses.emailEnc })
    .from(schema.emailAddresses)
    .where(and(eq(schema.emailAddresses.userId, userId), eq(schema.emailAddresses.isPrimary, true)))
    .limit(1);
  if (e) await assertSsoNotRequired(instanceId, decrypt(e.enc, `email_addresses.email:${e.id}`));
}
