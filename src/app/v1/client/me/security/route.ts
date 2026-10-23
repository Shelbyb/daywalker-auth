import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { requireSession } from "@/lib/auth/require-session";
import { hasPassword, linkedProviders } from "@/lib/auth/account";
import { listSecurityKeys } from "@/lib/auth/security-keys";
import { hasTwoFactor, remainingBackupCodes, smsAllowed, twoFactorMethods } from "@/lib/auth/mfa";

export const OPTIONS = preflight;

/** What the account page's security section needs. */
export const GET = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  const s = await requireSession(ctx.inst, ctx.refreshToken);
  const twoFactorEnabled = await hasTwoFactor(s.userId);
  const m = await twoFactorMethods(s.userId);
  return ctx.json({
    hasPassword: await hasPassword(s.userId),
    twoFactorEnabled,
    totpEnabled: m.totp,
    /** Masked number, e.g. "+1 ••• ••• 0100", or null. */
    smsPhone: m.sms,
    smsAvailable: smsAllowed(ctx.inst),
    securityKeys: await listSecurityKeys(s.userId),
    backupCodesRemaining: twoFactorEnabled ? await remainingBackupCodes(s.userId) : 0,
    connectedAccounts: await linkedProviders(s.userId),
  });
});
