/**
 * Instance-wide protection settings: sign-up rules, the human check, and the two-factor requirement.
 * Shared by the backend API (`/v1/instance/protection`) and the dashboard.
 */
import { eq } from "drizzle-orm";
import { z } from "zod";
import { db, schema } from "../db";
import { errors } from "../http";
import { invalidateInstance } from "./instance";
import { encryptCaptchaSecret } from "./signup-protection";
import type { Instance } from "../db/schema";

const domainRe = /^(?=.{3,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const domains = z.array(z.string().trim().toLowerCase().regex(domainRe, "Enter domains like example.com")).max(200);

export const protectionInput = z
  .object({
    allowedDomains: domains.optional(),
    blockedDomains: domains.optional(),
    blockDisposableEmails: z.boolean().optional(),
    /** Turnstile keys; `null` turns the human check off. A site key alone keeps the stored secret. */
    captcha: z.object({ siteKey: z.string().trim().min(10).max(200).regex(/^[\w-]+$/), secretKey: z.string().trim().min(10).max(200).optional() }).nullable().optional(),
    requireTwoFactor: z.boolean().optional(),
    /** Days people have to set up two-factor after it becomes required (0 = right away). */
    twoFactorGraceDays: z.number().int().min(0).max(90).optional(),
  })
  .strict();

export function protectionView(inst: Instance) {
  const s = inst.settings;
  return {
    allowedDomains: s.signUpAllowedDomains ?? [],
    blockedDomains: s.signUpBlockedDomains ?? [],
    blockDisposableEmails: s.blockDisposableEmails === true,
    captcha: s.captchaSiteKey ? { provider: "turnstile", siteKey: s.captchaSiteKey, secretSet: !!inst.captchaSecretEnc } : null,
    requireTwoFactor: s.requireTwoFactor === true,
    twoFactorGraceUntil: s.requireTwoFactor ? (s.twoFactorGraceUntil ?? null) : null,
  };
}

export async function updateProtection(cached: Instance, raw: unknown) {
  const p = protectionInput.parse(raw);
  // Merge into the stored row, not a cached copy, so concurrent settings changes aren't lost.
  const [inst] = await db().select().from(schema.instances).where(eq(schema.instances.id, cached.id));
  const s = { ...inst.settings };
  const set: Partial<typeof schema.instances.$inferInsert> = {};
  if (p.allowedDomains) s.signUpAllowedDomains = [...new Set(p.allowedDomains)];
  if (p.blockedDomains) s.signUpBlockedDomains = [...new Set(p.blockedDomains)];
  if (p.blockDisposableEmails !== undefined) s.blockDisposableEmails = p.blockDisposableEmails;
  if (p.captcha === null) {
    s.captchaSiteKey = null;
    set.captchaSecretEnc = null;
  } else if (p.captcha) {
    if (!p.captcha.secretKey && !inst.captchaSecretEnc) throw errors.badRequest("captcha_secret_required", "Add the Turnstile secret key too");
    s.captchaSiteKey = p.captcha.siteKey;
    if (p.captcha.secretKey) set.captchaSecretEnc = encryptCaptchaSecret(inst.id, p.captcha.secretKey);
  }
  if (p.requireTwoFactor !== undefined) {
    const wasOn = s.requireTwoFactor === true;
    s.requireTwoFactor = p.requireTwoFactor;
    if (!p.requireTwoFactor) s.twoFactorGraceUntil = null;
    else if (!wasOn || p.twoFactorGraceDays !== undefined) s.twoFactorGraceUntil = new Date(Date.now() + (p.twoFactorGraceDays ?? 7) * 86_400_000).toISOString();
  }
  await db().update(schema.instances).set({ ...set, settings: s, updatedAt: new Date() }).where(eq(schema.instances.id, inst.id));
  await invalidateInstance(inst.id);
  const [fresh] = await db().select().from(schema.instances).where(eq(schema.instances.id, inst.id));
  return protectionView(fresh);
}
