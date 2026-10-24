/**
 * Self-service account deletion and data export.
 *
 * Both need RE-AUTHENTICATION in the request itself (a stolen session is not enough):
 *  - the password, when the account has one;
 *  - a second-factor code (or a security-key confirmation made in this session), when 2FA is on;
 *  - an emailed 6-digit code, when the account has neither (social or passkey sign-in only).
 * Wrong answers count toward the account lockout like any other failed attempt.
 *
 * Deletion: sign-out everywhere, a grace period (instance setting, default 14 days, 0 = immediate), sign-in refused
 * meanwhile, and a single-use cancel link by email. A purge job then deletes the user (cascade), removes organizations
 * they were the only member of, and strips the personal data out of their audit events.
 * Export: a JSON file of what we hold about the person, decrypted for them. Never password hashes, TOTP secrets,
 * backup-code hashes, token hashes, or the developer-only private metadata.
 */
import { and, eq, inArray, isNotNull, lte, or, sql } from "drizzle-orm";
import { z } from "zod";
import { db, schema } from "../db";
import { cache, rateLimit } from "../cache";
import { decrypt, decryptNullable, verifyPassword } from "../crypto";
import { env } from "../env";
import { errors } from "../http";
import { newToken, sha256 } from "../ids";
import { listAudit, record } from "../audit";
import { eraseDetailsFor } from "../audit-chain";
import { sendMail } from "../mail";
import { composeEmail } from "../email-templates";
import { emit } from "../webhooks";
import { issueCode, consumeCode } from "./codes";
import { confirmed, hasTwoFactor } from "./mfa";
import { publishableKey } from "./instance";
import * as lockout from "./lockout";
import type { Instance } from "../db/schema";

export const DEFAULT_GRACE_DAYS = 14;
export const MAX_GRACE_DAYS = 90;

export function deletionSettings(inst: Pick<Instance, "settings">) {
  const s = inst.settings.accountDeletion ?? {};
  const g = typeof s.graceDays === "number" && Number.isInteger(s.graceDays) && s.graceDays >= 0 && s.graceDays <= MAX_GRACE_DAYS ? s.graceDays : DEFAULT_GRACE_DAYS;
  return { enabled: s.enabled !== false, graceDays: g };
}

export const reauthInput = z.object({
  password: z.string().max(256).optional(),
  /** Authenticator, texted or backup code. Omit after confirming with a security key in the same session. */
  code: z.string().trim().max(64).optional(),
  /** From `POST me/reauth_code`, for accounts with no password and no two-factor. */
  emailCode: z.string().trim().max(10).optional(),
});
export type Reauth = z.infer<typeof reauthInput>;

async function primaryEmail(instanceId: string, userId: string) {
  const rows = await db()
    .select({ id: schema.emailAddresses.id, enc: schema.emailAddresses.emailEnc, primary: schema.emailAddresses.isPrimary })
    .from(schema.emailAddresses)
    .where(and(eq(schema.emailAddresses.userId, userId), eq(schema.emailAddresses.instanceId, instanceId)));
  const r = rows.find((x) => x.primary) ?? rows[0];
  return r ? decrypt(r.enc, `email_addresses.email:${r.id}`) : null;
}

/** What `reauthenticate` will ask for, so a UI can show the right fields. */
export async function reauthRequirements(userId: string) {
  const [pw] = await db().select({ u: schema.passwords.userId }).from(schema.passwords).where(eq(schema.passwords.userId, userId));
  const twoFactor = await hasTwoFactor(userId);
  return { password: !!pw, twoFactor, emailCode: !pw && !twoFactor };
}

/** For accounts with neither a password nor two-factor: emails a one-time confirmation code. */
export async function sendReauthCode(inst: Instance, userId: string) {
  const need = await reauthRequirements(userId);
  if (!need.emailCode) throw errors.badRequest("not_needed", "This account confirms with its password or second factor");
  if ((await rateLimit(`${inst.id}:reauth_code:${userId}`, 5, 3600)) < 0) throw errors.tooMany();
  const to = await primaryEmail(inst.id, userId);
  if (!to) throw errors.badRequest("no_email", "This account has no email address to send a code to");
  const code = await issueCode("reauth", userId);
  await sendMail({ to, ...(await composeEmail(inst, "reauth_code", { code, expires_minutes: "10" })) });
}

/** Throws unless the caller proved who they are right now. Wrong answers count toward lockout. */
export async function reauthenticate(inst: Instance, userId: string, sessionId: string, input: Reauth) {
  const need = await reauthRequirements(userId);
  const subject = { userId };
  if (need.password) {
    if (!input.password) throw errors.badRequest("credentials_required", "Enter your password to continue");
    const slot = await lockout.reserve(inst, subject, "pw");
    const [row] = await db().select({ hash: schema.passwords.hash }).from(schema.passwords).where(eq(schema.passwords.userId, userId));
    if (!row || !(await verifyPassword(row.hash, input.password))) {
      await lockout.failed(inst, subject, slot, "password");
      void record(inst.id, "user.sign_in_failed", { target: userId, data: { reason: "wrong_password", purpose: "reauth" } });
      throw errors.badRequest("invalid_credentials", "Your password is incorrect");
    }
    await lockout.succeeded(inst, subject, "pw");
  }
  if (need.twoFactor) {
    const slot = await lockout.reserve(inst, subject, "mf");
    if (!(await confirmed(userId, sessionId, input.code))) {
      if (!input.code) throw errors.badRequest("credentials_required", "Enter a code from your authenticator or a backup code, or confirm with your security key");
      await lockout.failed(inst, subject, slot, "second_factor");
      void record(inst.id, "user.two_factor_failed", { target: userId, data: { purpose: "reauth" } });
      throw errors.badRequest("invalid_code", "That code is incorrect");
    }
    await lockout.succeeded(inst, subject, "mf");
  }
  if (need.emailCode) {
    if (!input.emailCode) throw errors.badRequest("credentials_required", "Request a confirmation code by email and enter it");
    if (!(await consumeCode("reauth", userId, input.emailCode))) throw errors.badRequest("invalid_code", "That code is incorrect or has expired");
  }
}

// ---------- Deletion ----------

export async function assertNotPendingDeletion(instanceId: string, userId: string) {
  const [u] = await db().select({ at: schema.users.deletionScheduledAt }).from(schema.users).where(and(eq(schema.users.id, userId), eq(schema.users.instanceId, instanceId)));
  if (u?.at)
    throw errors.forbidden(`This account is scheduled for deletion on ${u.at.toISOString().slice(0, 10)}. Use the cancel link in the confirmation email to keep it`).withCode("account_pending_deletion");
}

/** Organizations where this user is the only admin of a team that has other members (deleting them would orphan it). */
async function soleAdminOrgs(userId: string) {
  const rows = (await db().execute(sql`
    select o.id, o.name from memberships m
    join organizations o on o.id = m.org_id
    where m.user_id = ${userId} and m.role = 'admin'
      and not exists (select 1 from memberships a where a.org_id = m.org_id and a.role = 'admin' and a.user_id <> ${userId})
      and exists (select 1 from memberships x where x.org_id = m.org_id and x.user_id <> ${userId})`)) as unknown as { id: string; name: string }[];
  return rows;
}

export async function requestDeletion(inst: Instance, userId: string, sessionId: string, impersonated: boolean, input: Reauth) {
  const cfg = deletionSettings(inst);
  if (!cfg.enabled) throw errors.forbidden("Deleting accounts yourself is turned off for this application").withCode("account_deletion_disabled");
  if (impersonated) throw errors.forbidden("Not available while signed in as someone else").withCode("impersonation_forbidden");
  if ((await rateLimit(`${inst.id}:del_req:${userId}`, 5, 3600)) < 0) throw errors.tooMany();
  await assertNotPendingDeletion(inst.id, userId).then(
    () => undefined,
    () => { throw errors.conflict("already_scheduled", "Deletion is already scheduled for this account"); },
  );
  const orgs = await soleAdminOrgs(userId);
  if (orgs.length)
    throw errors.conflict("sole_org_admin", `You are the only admin of ${orgs.map((o) => o.name).join(", ")}. Make someone else an admin or delete the organization first`);
  await reauthenticate(inst, userId, sessionId, input);

  const token = newToken();
  const now = new Date();
  const scheduled = new Date(now.getTime() + cfg.graceDays * 86_400_000);
  await db().update(schema.users).set({ deletionRequestedAt: now, deletionScheduledAt: scheduled, deletionTokenHash: sha256(token) }).where(eq(schema.users.id, userId));
  // Out everywhere, this device included.
  const revoked = await db()
    .update(schema.sessions)
    .set({ status: "revoked" })
    .where(and(eq(schema.sessions.userId, userId), eq(schema.sessions.status, "active")))
    .returning({ h: schema.sessions.refreshTokenHash });
  if (revoked.length) await cache().del(...revoked.map((r) => `sess:${r.h}`));
  void record(inst.id, "user.deletion_requested", { actor: { type: "user", id: userId }, target: userId, data: { scheduledFor: scheduled.toISOString(), graceDays: cfg.graceDays } });
  void emit(inst.id, "user.deletion_requested", { userId, scheduledFor: scheduled.toISOString() });
  if (cfg.graceDays === 0) {
    await purgeUser(inst, userId, "self_service");
    return { scheduledFor: scheduled.toISOString(), deleted: true };
  }
  const to = await primaryEmail(inst.id, userId);
  if (to) {
    const link = `${env().APP_URL}/cancel-deletion?pk=${encodeURIComponent(publishableKey(inst))}#token=${encodeURIComponent(token)}`;
    await sendMail({ to, ...(await composeEmail(inst, "account_deletion", { link, date: scheduled.toISOString().slice(0, 10) })) }).catch((e) => console.error("[deletion] mail failed", (e as Error).message));
  }
  return { scheduledFor: scheduled.toISOString(), deleted: false };
}

async function afterCancel(inst: Instance, userId: string, by: { type: "user" | "developer" | "api"; id?: string; via: string }) {
  void record(inst.id, "user.deletion_canceled", { actor: { type: by.type, id: by.id }, target: userId, data: { via: by.via } });
  void emit(inst.id, "user.deletion_canceled", { userId, via: by.via });
}

/** The emailed link. Single use. The person then signs in as usual. */
export async function cancelDeletionByToken(inst: Instance, token: string) {
  const [row] = await db()
    .update(schema.users)
    .set({ deletionRequestedAt: null, deletionScheduledAt: null, deletionTokenHash: null })
    .where(and(eq(schema.users.instanceId, inst.id), eq(schema.users.deletionTokenHash, sha256(token)), isNotNull(schema.users.deletionScheduledAt)))
    .returning({ id: schema.users.id });
  if (!row) throw errors.badRequest("invalid_cancel_link", "This link has expired or was already used");
  await afterCancel(inst, row.id, { type: "user", id: row.id, via: "email_link" });
}

/** Developer (dashboard or backend API). Returns whether a deletion was pending. */
export async function cancelDeletion(inst: Instance, userId: string, by: { type: "developer" | "api"; id?: string }) {
  const [row] = await db()
    .update(schema.users)
    .set({ deletionRequestedAt: null, deletionScheduledAt: null, deletionTokenHash: null })
    .where(and(eq(schema.users.id, userId), eq(schema.users.instanceId, inst.id), isNotNull(schema.users.deletionScheduledAt)))
    .returning({ id: schema.users.id });
  if (!row) {
    const [u] = await db().select({ id: schema.users.id }).from(schema.users).where(and(eq(schema.users.id, userId), eq(schema.users.instanceId, inst.id)));
    if (!u) throw errors.notFound("User not found");
    return false;
  }
  await afterCancel(inst, userId, { ...by, via: "admin" });
  return true;
}

/** Deletes the user for good: orgs they alone belonged to, personal data in their audit trail, then the user (cascade). */
async function purgeUser(inst: Instance, userId: string, reason: string) {
  const alone = (await db().execute(sql`
    select m.org_id as id from memberships m
    where m.user_id = ${userId} and not exists (select 1 from memberships x where x.org_id = m.org_id and x.user_id <> ${userId})`)) as unknown as { id: string }[];
  if (alone.length) await db().delete(schema.organizations).where(and(inArray(schema.organizations.id, alone.map((a) => a.id)), eq(schema.organizations.instanceId, inst.id)));
  // Keep the fact that things happened; drop the IP addresses, browsers and other detail.
  // (Marked as erased, not just emptied, so the audit hash chain still verifies.)
  await eraseDetailsFor(inst.id, userId);
  const { deleteUser } = await import("./users");
  await deleteUser(inst.id, userId);
  void record(inst.id, "user.deleted", { actor: { type: "system" }, target: userId, data: { reason } });
}

/** The job: deletes everyone whose grace period has ended. Safe to run on every server at once. */
export async function purgeDueDeletions(limit = 50) {
  const due = await db()
    .select({ id: schema.users.id, instanceId: schema.users.instanceId })
    .from(schema.users)
    .where(and(isNotNull(schema.users.deletionScheduledAt), lte(schema.users.deletionScheduledAt, new Date())))
    .limit(limit);
  let n = 0;
  const { getInstance } = await import("./instance");
  for (const u of due) {
    // One server wins each user.
    if (!(await cache().set(`purge:${u.id}`, "1", "EX", 300, "NX"))) continue;
    try {
      const inst = await getInstance(u.instanceId);
      if (!inst) continue;
      await purgeUser(inst, u.id, "self_service");
      n++;
    } catch (e) {
      if ((e as { status?: number }).status !== 404) console.error("[deletion] purge failed", u.id, (e as Error).message);
    }
  }
  return n;
}

// ---------- Export ----------

const iso = (d: Date | null | undefined) => (d ? d.toISOString() : null);

export async function exportUserData(inst: Instance, userId: string, sessionId: string, impersonated: boolean, input: Reauth) {
  if (impersonated) throw errors.forbidden("Not available while signed in as someone else").withCode("impersonation_forbidden");
  if ((await rateLimit(`${inst.id}:export:${userId}`, 3, 3600)) < 0) throw errors.tooMany();
  await reauthenticate(inst, userId, sessionId, input);

  const [u] = await db().select().from(schema.users).where(and(eq(schema.users.id, userId), eq(schema.users.instanceId, inst.id)));
  if (!u) throw errors.notFound("User not found");
  const d = db();
  const [emails, sessions, oauth, totp, sms, backup, passkeys, keys, legal, orgs, pw] = await Promise.all([
    d.select().from(schema.emailAddresses).where(eq(schema.emailAddresses.userId, userId)),
    d.select().from(schema.sessions).where(eq(schema.sessions.userId, userId)),
    d.select().from(schema.oauthAccounts).where(eq(schema.oauthAccounts.userId, userId)),
    d.select({ verifiedAt: schema.mfaTotp.verifiedAt, createdAt: schema.mfaTotp.createdAt }).from(schema.mfaTotp).where(eq(schema.mfaTotp.userId, userId)),
    d.select().from(schema.mfaSms).where(eq(schema.mfaSms.userId, userId)),
    d.select({ usedAt: schema.backupCodes.usedAt }).from(schema.backupCodes).where(eq(schema.backupCodes.userId, userId)),
    d.select({ name: schema.passkeys.name, deviceType: schema.passkeys.deviceType, backedUp: schema.passkeys.backedUp, lastUsedAt: schema.passkeys.lastUsedAt, createdAt: schema.passkeys.createdAt }).from(schema.passkeys).where(eq(schema.passkeys.userId, userId)),
    d.select({ name: schema.mfaSecurityKeys.name, lastUsedAt: schema.mfaSecurityKeys.lastUsedAt, createdAt: schema.mfaSecurityKeys.createdAt }).from(schema.mfaSecurityKeys).where(eq(schema.mfaSecurityKeys.userId, userId)),
    d.select().from(schema.legalAcceptances).where(eq(schema.legalAcceptances.userId, userId)),
    d
      .select({ id: schema.organizations.id, name: schema.organizations.name, slug: schema.organizations.slug, role: schema.memberships.role, joinedAt: schema.memberships.createdAt })
      .from(schema.memberships)
      .innerJoin(schema.organizations, eq(schema.organizations.id, schema.memberships.orgId))
      .where(and(eq(schema.memberships.userId, userId), eq(schema.organizations.instanceId, inst.id))),
    d.select({ updatedAt: schema.passwords.updatedAt }).from(schema.passwords).where(eq(schema.passwords.userId, userId)),
  ]);
  const activity: Awaited<ReturnType<typeof listAudit>>["data"] = [];
  let cursor: string | undefined;
  for (let i = 0; i < 5; i++) {
    const page = await listAudit(inst.id, { target: userId, limit: 200, before: cursor });
    activity.push(...page.data);
    if (!page.nextCursor) break;
    cursor = page.nextCursor;
  }

  const data = {
    exportedAt: new Date().toISOString(),
    service: inst.name,
    notes: "Secrets (password hash, authenticator secret, backup codes, session tokens) are never included. Application-private metadata is held by the app, not by this service's user record.",
    profile: {
      id: u.id,
      firstName: decryptNullable(u.firstNameEnc, `users.first_name:${u.id}`),
      lastName: decryptNullable(u.lastNameEnc, `users.last_name:${u.id}`),
      imageUrl: u.imageUrl,
      publicMetadata: u.publicMetadata,
      createdAt: iso(u.createdAt),
      updatedAt: iso(u.updatedAt),
      lastSignInAt: iso(u.lastSignInAt),
    },
    emailAddresses: emails.map((e) => ({ email: decrypt(e.emailEnc, `email_addresses.email:${e.id}`), primary: e.isPrimary, verifiedAt: iso(e.verifiedAt), createdAt: iso(e.createdAt) })),
    password: { set: pw.length > 0, changedAt: iso(pw[0]?.updatedAt) },
    connectedAccounts: oauth.map((o) => ({ provider: o.provider, email: decryptNullable(o.emailEnc, `oauth_accounts.email:${o.id}`), connectedAt: iso(o.createdAt) })),
    twoFactor: {
      authenticatorApp: totp.length ? { enabled: !!totp[0].verifiedAt, since: iso(totp[0].createdAt) } : null,
      sms: sms.length ? { phone: decrypt(sms[0].phoneEnc, `mfa_sms.phone:${userId}`), verified: !!sms[0].verifiedAt } : null,
      securityKeys: keys.map((k) => ({ name: k.name, lastUsedAt: iso(k.lastUsedAt), addedAt: iso(k.createdAt) })),
      backupCodes: { total: backup.length, unused: backup.filter((b) => !b.usedAt).length },
    },
    passkeys: passkeys.map((p) => ({ name: p.name, type: p.deviceType, backedUp: p.backedUp, lastUsedAt: iso(p.lastUsedAt), addedAt: iso(p.createdAt) })),
    sessions: sessions.filter((s) => !s.impersonatorId).map((s) => ({
      id: s.id,
      status: s.status,
      device: decryptNullable(s.userAgentEnc, `sessions.user_agent:${s.id}`),
      ipAddress: decryptNullable(s.ipAddressEnc, `sessions.ip_address:${s.id}`),
      lastActiveAt: iso(s.lastActiveAt),
      createdAt: iso(s.createdAt),
      expiresAt: iso(s.expiresAt),
    })),
    organizations: orgs.map((o) => ({ ...o, joinedAt: iso(o.joinedAt) })),
    termsAccepted: legal.map((l) => ({ version: l.version, method: l.method, acceptedAt: iso(l.acceptedAt) })),
    activity: activity.map((a) => ({ time: iso(a.createdAt as Date), event: a.type, by: a.actor.type, details: a.data })),
  };
  void record(inst.id, "user.data_exported", { actor: { type: "user", id: userId }, target: userId, data: { sections: Object.keys(data).length, activityEvents: activity.length } });
  return data;
}
