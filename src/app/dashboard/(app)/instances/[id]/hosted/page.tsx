import Link from "next/link";
import { requireUser } from "../../../guard";
import { addDomainAction, removeDomainAction, saveBrandingAction, saveRedirectsAction, verifyDomainAction } from "../../../actions";
import { ActionForm } from "../../../forms";
import { Badge, Card, CopyButton, Field, PageHeader } from "../../../ui";
import { btnCls, inputCls } from "../../../styles";
import { details } from "../../../server";
import { autoVerifyPending, listDomains } from "@/lib/hosted";
import { publishableKey } from "@/lib/auth/instance";
import { env } from "@/lib/env";
import { ownedInstance } from "@/lib/dashboard";
import { HelpLink } from "../../../help";

export const metadata = { title: "Account Portal" };

const TABS = [["overview", "Overview"], ["redirects", "Redirects"], ["customization", "Customization"]] as const;

function UrlRow({ label, url }: { label: string; url: string }) {
  return (
    <div className="py-3">
      <p className="mb-1.5 text-sm font-medium">{label}</p>
      <div className="flex items-center gap-2">
        <code className="min-w-0 flex-1 truncate rounded-md border border-stone-200 bg-stone-50 px-3 py-1.5 text-xs">{url}</code>
        <CopyButton value={url} />
        <a href={url} target="_blank" rel="noreferrer" aria-label={`Open ${label}`} className="text-stone-500 hover:text-ink">↗</a>
      </div>
    </div>
  );
}

export default async function AccountPortalPage({ params, searchParams }: { params: Promise<{ id: string }>; searchParams: Promise<{ tab?: string }> }) {
  const { id } = await params;
  const sp = (await searchParams).tab ?? "";
  const tab = TABS.some(([t]) => t === sp) ? sp : "overview";
  const { userId } = await requireUser(`/dashboard/instances/${encodeURIComponent(id)}/hosted`);
  const inst = await details(userId, id);
  const full = await ownedInstance(userId, id);
  const b = full.settings.branding ?? {};
  const r = full.settings.redirects ?? {};
  await autoVerifyPending(id);
  const domains = await listDomains(userId, id);
  const pk = publishableKey(full);
  const verified = domains.find((d) => d.verifiedAt);
  const portal = verified ? `https://${verified.hostname}` : `${env().APP_URL}/h/${pk}`;
  const appHost = process.env.CUSTOM_DOMAIN_CNAME_TARGET || new URL(env().APP_URL).hostname;
  const here = `/dashboard/instances/${encodeURIComponent(id)}/hosted`;
  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4">
        <PageHeader title="Account Portal"
          description="A fully hosted sign-in, sign-up and account experience, on our domain or yours. Use it instead of the SDK components, or alongside them." />
        <a href={`${portal}/sign-in`} target="_blank" rel="noreferrer" className={btnCls.primary}>View ↗</a>
      </div>
      <nav aria-label="Account Portal" className="flex gap-6 border-b border-stone-200">
        {TABS.map(([t, label]) => (
          <Link key={t} href={`${here}?tab=${t}`} aria-current={tab === t ? "page" : undefined}
            className={`-mb-px border-b-2 py-2 text-sm font-medium ${tab === t ? "border-ink text-ink" : "border-transparent text-stone-500 hover:text-ink"}`}>{label}</Link>
        ))}
      </nav>

      {tab === "overview" && (<>
        <Card>
          <h2 className="mb-1 font-semibold">Authentication <HelpLink slug="guides/account-portal" label="Account Portal" /></h2>
          <div className="divide-y divide-stone-200">
            <UrlRow label="Sign in" url={`${portal}/sign-in`} />
            <UrlRow label="Sign up" url={`${portal}/sign-up`} />
            <UrlRow label="Forgot password" url={`${portal}/forgot-password`} />
            <UrlRow label="Unauthorized sign in" url={`${portal}/unauthorized-sign-in`} />
          </div>
        </Card>
        <Card>
          <h2 className="mb-1 font-semibold">Users</h2>
          <UrlRow label="User profile" url={`${portal}/account`} />
          <p className="mt-2 text-xs text-stone-500">Add <code>?redirect_url=</code> to send people back to a page in your app. It must be on one of your allowed origins.</p>
        </Card>
      </>)}

      {tab === "redirects" && (
        <Card>
          <h2 className="mb-1 font-semibold">User redirects <HelpLink slug="guides/account-portal" label="Account Portal redirects" /></h2>
          <p className="mb-4 text-sm text-stone-500">Where the Account Portal sends people after key actions when the link has no <code>redirect_url</code>. Each URL must be on one of your allowed origins ({inst.allowedOrigins.join(", ") || "none yet, add one under Sign-in & security"}).</p>
          <ActionForm action={saveRedirectsAction} submit="Save redirects" className="max-w-xl space-y-5">
            <input type="hidden" name="instanceId" value={inst.id} />
            <Field label="After sign-up fallback" hint="Used when the URL has no redirect_url."><input name="afterSignUp" type="url" defaultValue={r.afterSignUp ?? ""} placeholder="https://your-app.example/onboarding" className={inputCls} /></Field>
            <Field label="After sign-in fallback" hint="Used when the URL has no redirect_url."><input name="afterSignIn" type="url" defaultValue={r.afterSignIn ?? ""} placeholder="https://your-app.example/dashboard" className={inputCls} /></Field>
            <Field label="After logo click" hint="Where your logo on the portal links to."><input name="afterLogoClick" type="url" defaultValue={r.afterLogoClick ?? ""} placeholder="https://your-app.example/" className={inputCls} /></Field>
          </ActionForm>
        </Card>
      )}

      {tab === "customization" && (<>
        <Card>
          <h2 className="mb-3 font-semibold">Appearance <HelpLink slug="guides/account-portal" label="Account Portal appearance" /></h2>
          <ActionForm action={saveBrandingAction} submit="Save appearance" className="max-w-xl space-y-5">
            <input type="hidden" name="instanceId" value={inst.id} />
            <Field label="Logo URL" hint="https image shown above the form."><input name="logoUrl" type="url" defaultValue={b.logoUrl ?? ""} placeholder="https://example.com/logo.png" className={inputCls} /></Field>
            <Field label="Heading" hint="Replaces the default title, for example your product name."><input name="title" maxLength={80} defaultValue={b.title ?? ""} className={inputCls} /></Field>
            <Field label="Button color" hint="Hex, like #ff6a3d."><input name="primaryColor" maxLength={7} defaultValue={b.primaryColor ?? ""} placeholder="#ff6a3d" className={inputCls} /></Field>
            <Field label="Background color" hint="Hex, like #f5f5f4."><input name="backgroundColor" maxLength={7} defaultValue={b.backgroundColor ?? ""} placeholder="#f5f5f4" className={inputCls} /></Field>
          </ActionForm>
        </Card>
        <Card>
          <h2 className="mb-1 font-semibold">Custom domain <HelpLink slug="guides/account-portal" label="Custom domains" /></h2>
          <p className="mb-4 text-sm text-stone-500">Serve the Account Portal from your own hostname, such as accounts.example.com. The default address then redirects there.</p>
          <ul className="mb-5 space-y-4">
            {domains.map((d) => (
              <li key={d.id} className="rounded-lg border border-stone-200 p-4 text-sm">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono">{d.hostname}</span>
                  <Badge tone={d.verifiedAt ? "good" : "warn"}>{d.verifiedAt ? "Verified" : "Pending verification"}</Badge>
                </div>
                {!d.verifiedAt && (
                  <div className="mt-3 space-y-1 text-xs text-stone-600">
                    <p>Where you manage DNS, add one CNAME record: <code>{d.hostname}</code> &rarr; <code>{appHost}</code> (DNS only, not proxied).</p>
                    <p>We detect it automatically (reload this page to re-check) and set up the certificate. DNS changes can take a while to propagate.</p>
                  </div>
                )}
                <div className="mt-3 flex gap-2">
                  {!d.verifiedAt && (
                    <ActionForm action={verifyDomainAction} submit="Check now" className="">
                      <input type="hidden" name="instanceId" value={inst.id} /><input type="hidden" name="domainId" value={d.id} />
                    </ActionForm>
                  )}
                  <ActionForm action={removeDomainAction} submit="Remove" tone="danger" className="">
                    <input type="hidden" name="instanceId" value={inst.id} /><input type="hidden" name="domainId" value={d.id} />
                  </ActionForm>
                </div>
              </li>
            ))}
          </ul>
          <ActionForm action={addDomainAction} submit="Add domain" resetOnSuccess className="max-w-xl space-y-4">
            <input type="hidden" name="instanceId" value={inst.id} />
            <Field label="Hostname"><input name="hostname" required placeholder="accounts.example.com" className={inputCls} /></Field>
          </ActionForm>
        </Card>
      </>)}
    </div>
  );
}
