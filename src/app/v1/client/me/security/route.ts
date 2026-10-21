import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { requireSession } from "@/lib/auth/require-session";
import { hasPassword, linkedProviders } from "@/lib/auth/account";
import { hasTwoFactor, remainingBackupCodes } from "@/lib/auth/mfa";

export const OPTIONS = preflight;

/** What the account page's security section needs. */
export const GET = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  const s = await requireSession(ctx.inst, ctx.refreshToken);
  const twoFactorEnabled = await hasTwoFactor(s.userId);
  return ctx.json({
    hasPassword: await hasPassword(s.userId),
    twoFactorEnabled,
    backupCodesRemaining: twoFactorEnabled ? await remainingBackupCodes(s.userId) : 0,
    connectedAccounts: await linkedProviders(s.userId),
  });
});
