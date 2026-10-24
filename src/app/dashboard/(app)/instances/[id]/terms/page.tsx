import Link from "next/link";
import { requireUser } from "../../../guard";
import { updateLegalAction } from "../../../actions";
import { ActionForm } from "../../../forms";
import { Card, Field, PageHeader, Toggle } from "../../../ui";
import { inputCls } from "../../../styles";
import { details } from "../../../server";

export const metadata = { title: "Terms" };

export default async function TermsPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const { userId } = await requireUser(`/dashboard/instances/${encodeURIComponent(id)}/terms`);
  const inst = await details(userId, id);
  const l = inst.legal;
  return (
    <div className="space-y-6">
      <PageHeader
        title="Terms"
        description={<>Ask new users to accept your terms of service and privacy policy when they sign up, and keep a record that they did. See the <Link href="/docs/guides/terms-acceptance" className="font-medium underline decoration-dawn decoration-2 underline-offset-4">guide</Link>.</>}
      />
      <Card>
        <ActionForm action={updateLegalAction} submit="Save terms settings" className="max-w-xl space-y-5">
          <input type="hidden" name="instanceId" value={inst.id} />
          <Toggle name="required" defaultChecked={l.required} label="Require new users to accept the terms" />
          <Field label="Terms of service URL" hint="Required when acceptance is on. Must be https.">
            <input name="termsUrl" type="url" defaultValue={l.termsUrl ?? ""} placeholder="https://example.com/terms" className={inputCls} />
          </Field>
          <Field label="Privacy policy URL (optional)">
            <input name="privacyUrl" type="url" defaultValue={l.privacyUrl ?? ""} placeholder="https://example.com/privacy" className={inputCls} />
          </Field>
          <Field label="Version" hint="Any label for this edition of your terms, such as a date. Each acceptance is saved with the version, so change it whenever your terms change. It applies to people who sign up after the change.">
            <input name="version" required maxLength={40} defaultValue={l.version} placeholder="2026-10-21" className={inputCls} />
          </Field>
        </ActionForm>
      </Card>
    </div>
  );
}
