import { Suspense } from "react";
import { listProviders } from "@/lib/dashboard";
import { requireUser } from "../../../guard";
import { saveProviderAction, setProviderEnabledAction } from "../../../actions";
import { ActionForm } from "../../../forms";
import { Badge, Card, CodeBlock, Field, PageHeader, Skeleton, Toggle } from "../../../ui";
import { inputCls } from "../../../styles";
import { guarded } from "../../../server";

export const metadata = { title: "Social sign-in" };

/** Where to create the app, and what's different about each provider. */
const HELP: Record<string, string> = {
  google: "Google Cloud console → APIs & Services → Credentials → OAuth client ID (Web application).",
  github: "GitHub → Settings → Developer settings → OAuth Apps.",
  microsoft: "Microsoft Entra admin center → App registrations. Work and school emails are only trusted when Microsoft marks the domain as verified (add the optional claim xms_edov).",
  apple: "Apple Developer → Certificates, IDs & Profiles: create a Services ID (the client ID) and a Sign in with Apple key. Paste the whole .p8 key as the client secret.",
  discord: "Discord Developer Portal → Applications → OAuth2.",
  gitlab: "GitLab → Preferences → Applications, with the openid, email and profile scopes. Leave the URL empty for gitlab.com.",
  oidc: "Any OpenID Connect provider (Okta, Auth0, Keycloak, Zitadel…). Enter its issuer URL; we read the rest from its discovery document.",
};

async function Providers({ userId, id }: { userId: string; id: string }) {
  const providers = await guarded(() => listProviders(userId, id));
  return (
    <div className="grid gap-6 lg:grid-cols-2">
      {providers.map((p) => {
        const name = p.label;
        return (
          <Card
            key={p.provider}
            title={name}
            description={
              <>
                {p.configured ? (p.enabled ? <Badge tone="good">Enabled</Badge> : <Badge>Disabled</Badge>) : <Badge>Not set up</Badge>}
              </>
            }
          >
            <div className="space-y-4">
              <p className="text-sm text-stone-600">{HELP[p.provider]}</p>
              <CodeBlock label={`Redirect URI (paste this into the ${name} developer console)`} value={p.redirectUri} />
              <ActionForm action={saveProviderAction} submit="Save" className="space-y-4">
                <input type="hidden" name="instanceId" value={id} />
                <input type="hidden" name="provider" value={p.provider} />
                <Field label="Client ID">
                  <input name="clientId" required defaultValue={p.clientId ?? ""} autoComplete="off" spellCheck={false} className={`${inputCls} font-mono`} />
                </Field>
                {p.provider === "apple" ? (
                  <Field label="Private key (.p8)" hint="Encrypted when saved and never shown again, so paste it each time you save.">
                    <textarea name="clientSecret" required rows={4} autoComplete="off" spellCheck={false} placeholder="-----BEGIN PRIVATE KEY-----" className={`${inputCls} font-mono text-xs`} />
                  </Field>
                ) : (
                  <Field label="Client secret" hint="Encrypted when saved and never shown again, so enter it each time you save.">
                    <input name="clientSecret" type="password" required autoComplete="off" spellCheck={false} className={`${inputCls} font-mono`} />
                  </Field>
                )}
                {p.provider === "apple" && (
                  <div className="grid grid-cols-2 gap-3">
                    <Field label="Team ID"><input name="teamId" required maxLength={10} defaultValue={p.settings.teamId ?? ""} className={`${inputCls} font-mono`} /></Field>
                    <Field label="Key ID"><input name="keyId" required maxLength={10} defaultValue={p.settings.keyId ?? ""} className={`${inputCls} font-mono`} /></Field>
                  </div>
                )}
                {p.provider === "microsoft" && (
                  <Field label="Tenant" hint="Leave empty for any Microsoft account. Use a tenant ID to allow only your organization.">
                    <input name="tenant" maxLength={100} defaultValue={p.settings.tenant ?? ""} placeholder="common" className={`${inputCls} font-mono`} />
                  </Field>
                )}
                {p.provider === "gitlab" && (
                  <Field label="Self-hosted GitLab URL (optional)">
                    <input name="issuer" type="url" maxLength={500} defaultValue={p.settings.issuer ?? ""} placeholder="https://gitlab.example.com" className={`${inputCls} font-mono`} />
                  </Field>
                )}
                {p.provider === "oidc" && (
                  <>
                    <Field label="Issuer URL" hint="Must use https. Its discovery document must name this same issuer.">
                      <input name="issuer" type="url" required maxLength={500} defaultValue={p.settings.issuer ?? ""} placeholder="https://login.example.com" className={`${inputCls} font-mono`} />
                    </Field>
                    <Field label="Button label" hint='Shown as "Continue with …".'>
                      <input name="displayName" maxLength={40} defaultValue={p.settings.displayName ?? ""} placeholder="Okta" className={inputCls} />
                    </Field>
                  </>
                )}
                <Toggle name="enabled" defaultChecked={p.enabled} label={<>Enable {name} sign-in</>} />
              </ActionForm>
              {p.configured && (
                <ActionForm action={setProviderEnabledAction} submit={p.enabled ? `Disable ${name}` : `Enable ${name}`} tone="ghost" className="space-y-2">
                  <input type="hidden" name="instanceId" value={id} />
                  <input type="hidden" name="provider" value={p.provider} />
                  <input type="hidden" name="enabled" value={p.enabled ? "false" : "true"} />
                </ActionForm>
              )}
            </div>
          </Card>
        );
      })}
    </div>
  );
}

export default async function SocialPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const { userId } = await requireUser(`/dashboard/instances/${encodeURIComponent(id)}/social`);
  return (
    <div className="space-y-6">
      <PageHeader title="Social sign-in" description="Let people sign in with an account they already have: Google, GitHub, Microsoft, Apple, Discord, GitLab or any OpenID Connect provider. Create an app with the provider, then paste its details here. Only verified email addresses are ever linked to accounts." />
      <Suspense fallback={<Skeleton lines={5} />}>
        <Providers userId={userId} id={id} />
      </Suspense>
    </div>
  );
}
