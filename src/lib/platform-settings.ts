/**
 * Settings the whole platform uses: the email provider (Resend) and SMS provider (Twilio Verify).
 * Edited by platform admins in /dashboard/platform/settings; anything not set there falls back to
 * the environment. Secrets are encrypted in Postgres and only ever decrypted into process memory
 * (never Valkey), cached for a few seconds so a change reaches every process quickly.
 */
import { eq } from "drizzle-orm";
import { z } from "zod";
import { db, schema } from "./db";
import { decryptNullable, encryptNullable } from "./crypto";
import { env } from "./env";

const ROW = "default";
const TTL_MS = 15_000;

export type EffectiveSettings = {
  mailFrom: string;
  resendApiKey: string | null;
  twilio: { accountSid: string; authToken: string; verifyServiceSid: string } | null;
};

let memo: { at: number; value: EffectiveSettings } | null = null;

async function readRow() {
  try {
    const [row] = await db().select().from(schema.platformSettings).where(eq(schema.platformSettings.id, ROW));
    return row ?? null;
  } catch {
    return null; // table not migrated yet: env only
  }
}

/** What senders should use right now: the saved platform settings, else the environment. */
export async function effectiveSettings(): Promise<EffectiveSettings> {
  if (memo && Date.now() - memo.at < TTL_MS) return memo.value;
  const e = env();
  const row = await readRow();
  const resendApiKey = decryptNullable(row?.resendApiKeyEnc ?? null, `platform_settings.resend_api_key:${ROW}`) || e.RESEND_API_KEY || null;
  const sid = row?.twilioAccountSid || e.TWILIO_ACCOUNT_SID || "";
  const token = decryptNullable(row?.twilioAuthTokenEnc ?? null, `platform_settings.twilio_auth_token:${ROW}`) || e.TWILIO_AUTH_TOKEN || "";
  const service = row?.twilioVerifyServiceSid || e.TWILIO_VERIFY_SERVICE_SID || "";
  const value: EffectiveSettings = {
    mailFrom: row?.mailFrom || e.MAIL_FROM,
    resendApiKey,
    twilio: sid && token && service ? { accountSid: sid, authToken: token, verifyServiceSid: service } : null,
  };
  memo = { at: Date.now(), value };
  return value;
}

export const invalidatePlatformSettings = () => {
  memo = null;
};

export type SecretSource = "saved" | "env" | "unset";

/** For the settings page: never returns a secret, only whether one is set and where it comes from. */
export async function platformSettingsView() {
  const e = env();
  const row = await readRow();
  return {
    mailTransport: e.MAIL_TRANSPORT,
    mailFrom: row?.mailFrom ?? "",
    mailFromDefault: e.MAIL_FROM,
    resendApiKey: (row?.resendApiKeyEnc ? "saved" : e.RESEND_API_KEY ? "env" : "unset") as SecretSource,
    twilioAccountSid: row?.twilioAccountSid ?? "",
    twilioAuthToken: (row?.twilioAuthTokenEnc ? "saved" : e.TWILIO_AUTH_TOKEN ? "env" : "unset") as SecretSource,
    twilioVerifyServiceSid: row?.twilioVerifyServiceSid ?? "",
    twilioFromEnv: !!(e.TWILIO_ACCOUNT_SID && e.TWILIO_VERIFY_SERVICE_SID),
    updatedAt: row?.updatedAt ?? null,
    updatedBy: row?.updatedBy ?? null,
  };
}

const optional = <T extends z.ZodTypeAny>(s: T) => z.union([z.literal(""), s]).optional();

export const platformSettingsInput = z.object({
  mailFrom: optional(z.string().trim().max(200).regex(/^[^\r\n<>]*<[^\s@<>]+@[^\s@<>]+>$|^[^\s@<>]+@[^\s@<>]+$/, "Use an address like Acme <no-reply@acme.com>")),
  /** Empty keeps the saved key; `clearResendApiKey` removes it. */
  resendApiKey: optional(z.string().trim().regex(/^re_[A-Za-z0-9_-]{8,200}$/, "Resend API keys start with re_")),
  clearResendApiKey: z.boolean().optional(),
  twilioAccountSid: optional(z.string().trim().regex(/^AC[0-9a-fA-F]{32}$/, "The account SID is AC followed by 32 hex characters")),
  twilioAuthToken: optional(z.string().trim().min(16).max(200)),
  clearTwilioAuthToken: z.boolean().optional(),
  twilioVerifyServiceSid: optional(z.string().trim().regex(/^VA[0-9a-fA-F]{32}$/, "The Verify service SID is VA followed by 32 hex characters")),
});

/** Saves the settings. Returns which fields changed (names only, never values) for the audit log. */
export async function savePlatformSettings(actorId: string, raw: unknown) {
  const input = platformSettingsInput.parse(raw);
  const before = await readRow();
  const resendEnc = input.clearResendApiKey
    ? null
    : input.resendApiKey
      ? encryptNullable(input.resendApiKey, `platform_settings.resend_api_key:${ROW}`)
      : (before?.resendApiKeyEnc ?? null);
  const twilioEnc = input.clearTwilioAuthToken
    ? null
    : input.twilioAuthToken
      ? encryptNullable(input.twilioAuthToken, `platform_settings.twilio_auth_token:${ROW}`)
      : (before?.twilioAuthTokenEnc ?? null);
  const next = {
    mailFrom: input.mailFrom || null,
    resendApiKeyEnc: resendEnc,
    twilioAccountSid: input.twilioAccountSid || null,
    twilioAuthTokenEnc: twilioEnc,
    twilioVerifyServiceSid: input.twilioVerifyServiceSid || null,
    updatedBy: actorId,
    updatedAt: new Date(),
  };
  const changed: string[] = [];
  if ((before?.mailFrom ?? null) !== next.mailFrom) changed.push("mailFrom");
  if ((before?.resendApiKeyEnc ?? null) !== next.resendApiKeyEnc) changed.push("resendApiKey");
  if ((before?.twilioAccountSid ?? null) !== next.twilioAccountSid) changed.push("twilioAccountSid");
  if ((before?.twilioAuthTokenEnc ?? null) !== next.twilioAuthTokenEnc) changed.push("twilioAuthToken");
  if ((before?.twilioVerifyServiceSid ?? null) !== next.twilioVerifyServiceSid) changed.push("twilioVerifyServiceSid");
  await db().insert(schema.platformSettings).values({ id: ROW, ...next }).onConflictDoUpdate({ target: schema.platformSettings.id, set: next });
  invalidatePlatformSettings();
  return changed;
}
