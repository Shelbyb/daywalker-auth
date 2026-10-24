import { enabledProviders } from "./oauth";
import { legalOf } from "./legal";
import { emailCodeEnabled } from "./email-sign-in";
import { hasSso } from "./saml";
import { smsAllowed } from "./mfa";
import type { Instance } from "../db/schema";
import { captchaInfo } from "./signup-protection";
import { orgSettings } from "../org-settings";
import { sessionSettings } from "../session-settings";

/** Public instance settings the sign-in UI needs. Nothing secret: shared by the API and the hosted pages. */
export async function publicEnvironment(inst: Instance) {
  const list = await enabledProviders(inst.id);
  return {
    name: inst.name,
    oauthProviders: list.map((p) => p.id),
    oauthProviderLabels: Object.fromEntries(list.map((p) => [p.id, p.label])),
    passwordMinLength: inst.settings.passwordMinLength,
    legal: legalOf(inst),
    emailCodeSignIn: emailCodeEnabled(inst),
    ssoEnabled: await hasSso(inst.id),
    smsSecondFactor: await smsAllowed(inst),
    captcha: captchaInfo(inst),
    organizations: orgSettings(inst),
    sessions: (({ multiSession, inactivityTimeoutMinutes }) => ({ multiSession, inactivityTimeoutMinutes }))(sessionSettings(inst)),
  };
}
