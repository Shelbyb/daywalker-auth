import { requireUser } from "../../../guard";
import { addDomainAction, removeDomainAction, saveBrandingAction, verifyDomainAction } from "../../../actions";
import { ActionForm } from "../../../forms";
import { Badge, Card, Field, PageHeader } from "../../../ui";
import { inputCls } from "../../../styles";
import { details } from "../../../server";
import { autoVerifyPending, listDomains } from "@/lib/hosted";
import { publishableKey } from "@/lib/auth/instance";
import { env } from "@/lib/env";
import { ownedInstance } from "@/lib/dashboard";

export const metadata = { title: "Hosted pages" };

export default async function HostedPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const { userId } = await requireUser(`/dashboard/instances/${encodeURIComponent(id)}/hosted`);
  const inst = await details(userId, id);
  const full = await ownedInstance(userId, id);
  const b = full.settings.branding ?? {};
  await ownedInstance(userId, id);
  await autoVerifyPending(id);
  const domains = await listDomains(userId, id);
  const pk = publishableKey(full);
  const base = env().APP_URL;
  const appHost = new URL(base).hostname;
  return (
    <div className="space-y-6">
      <PageHeader
        title="Hosted pages"
        description="Skip the SDK components: send people to pages we host. They support everything the components do (sign-in, sign-up, email codes, social, passkeys, two-factor, password reset and the account page)."
      />
      <Card>
        <h2 className="mb-3 font-semibold">Page links</h2>
        <ul className="space-y-1 break-all font-mono text-xs text-stone-600">
          {["sign-in", "sign-up", "forgot-password", "account"].map((p) => (
            <li key={p}>{base}/{p}?pk={pk}&amp;redirect_url=https://your-app.example/</li>
          ))}
        </ul>
        <p className="mt-3 text-xs text-stone-500">The redirect URL must match one of your allowed origins. With a verified custom domain you can drop <code>pk</code> and use <code>https://your-domain/sign-in</code>.</p>
      </Card>
      <Card>
        <h2 className="mb-3 font-semibold">Appearance</h2>
        <ActionForm action={saveBrandingAction} submit="Save appearance" className="max-w-xl space-y-5">
          <input type="hidden" name="instanceId" value={inst.id} />
          <Field label="Logo URL" hint="https image shown above the form."><input name="logoUrl" type="url" defaultValue={b.logoUrl ?? ""} placeholder="https://example.com/logo.png" className={inputCls} /></Field>
          <Field label="Heading" hint="Replaces the default title, for example your product name."><input name="title" maxLength={80} defaultValue={b.title ?? ""} className={inputCls} /></Field>
          <Field label="Button color" hint="Hex, like #ff6a3d."><input name="primaryColor" maxLength={7} defaultValue={b.primaryColor ?? ""} placeholder="#ff6a3d" className={inputCls} /></Field>
          <Field label="Background color" hint="Hex, like #f5f5f4."><input name="backgroundColor" maxLength={7} defaultValue={b.backgroundColor ?? ""} placeholder="#f5f5f4" className={inputCls} /></Field>
        </ActionForm>
      </Card>
      <Card>
        <h2 className="mb-1 font-semibold">Custom domain</h2>
        <p className="mb-4 text-sm text-stone-500">Serve the hosted pages from your own hostname, such as auth.example.com.</p>
        <ul className="mb-5 space-y-4">
          {domains.map((d) => (
            <li key={d.id} className="rounded-lg border border-stone-200 p-4 text-sm">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono">{d.hostname}</span>
                <Badge tone={d.verifiedAt ? "good" : "warn"}>{d.verifiedAt ? "Verified" : "Pending verification"}</Badge>
              </div>
              {!d.verifiedAt && (
                <div className="mt-3 space-y-1 text-xs text-stone-600">
                  <p>Where you manage DNS, add one CNAME record: <code>{d.hostname}</code> &rarr; <code>{appHost}</code></p>
                  <p>That's all. We detect it automatically (reload this page to re-check) and set up the certificate. DNS changes can take a while to propagate.</p>
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
          <Field label="Hostname"><input name="hostname" required placeholder="auth.example.com" className={inputCls} /></Field>
        </ActionForm>
        <p className="mt-3 text-xs text-stone-500">A domain starts serving pages once its CNAME points at us.</p>
      </Card>
    </div>
  );
}
