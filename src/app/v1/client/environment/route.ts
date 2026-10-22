import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { enabledProviders } from "@/lib/auth/oauth";
import { legalOf } from "@/lib/auth/legal";
import { emailCodeEnabled } from "@/lib/auth/email-sign-in";
import { hasSso } from "@/lib/auth/saml";
import { smsAllowed } from "@/lib/auth/mfa";

export const OPTIONS = preflight;

/** Public instance settings the UI needs (which sign-in options to show). */
export const GET = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  return ctx.json({
    name: ctx.inst.name,
    ...(await enabledProviders(ctx.inst.id).then((list) => ({ oauthProviders: list.map((p) => p.id), oauthProviderLabels: Object.fromEntries(list.map((p) => [p.id, p.label])) }))),
    passwordMinLength: ctx.inst.settings.passwordMinLength,
    legal: legalOf(ctx.inst),
    emailCodeSignIn: emailCodeEnabled(ctx.inst),
    ssoEnabled: await hasSso(ctx.inst.id),
    smsSecondFactor: smsAllowed(ctx.inst),
  });
});
