import { enabledProviders } from "./oauth";
import { legalOf } from "./legal";
import { emailCodeEnabled } from "./email-sign-in";
import { passkeySignUpEnabled } from "./passkey-signup";
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
    /** "development" makes the components show a banner: this instance is not for real users. */
    instanceEnvironment: inst.environment,
    oauthProviders: list.map((p) => p.id),
    oauthProviderLabels: Object.fromEntries(list.map((p) => [p.id, p.label])),
    passwordMinLength: inst.settings.passwordMinLength,
    legal: legalOf(inst),
    emailCodeSignIn: emailCodeEnabled(inst),
    passkeySignUp: passkeySignUpEnabled(inst),
    ssoEnabled: await hasSso(inst.id),
    smsSecondFactor: await smsAllowed(inst),
    captcha: captchaInfo(inst),
    organizations: orgSettings(inst),
    sessions: (({ multiSession, inactivityTimeoutMinutes, deviceBinding }) => ({ multiSession, inactivityTimeoutMinutes, deviceBinding }))(sessionSettings(inst)),
  };
}
