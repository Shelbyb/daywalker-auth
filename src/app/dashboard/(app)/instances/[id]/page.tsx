import Link from "next/link";
import { requireUser } from "../../guard";
import { deleteInstanceAction } from "../../actions";
import { ActionForm } from "../../forms";
import { Card, CodeBlock, Field, PageHeader } from "../../ui";
import { inputCls } from "../../styles";
import { details } from "../../server";

export const metadata = { title: "Overview" };

export default async function Overview({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const { userId } = await requireUser(`/dashboard/instances/${encodeURIComponent(id)}`);
  const inst = await details(userId, id);
  const env = [
    `NEXT_PUBLIC_DAYWALKER_PUBLISHABLE_KEY=${inst.publishableKey}`,
    `NEXT_PUBLIC_DAYWALKER_AUTH_URL=${inst.frontendApi}`,
    `DAYWALKER_SECRET_KEY=sk_...   # paste a secret key from the API keys tab`,
  ].join("\n");
  return (
    <div className="space-y-6">
      <PageHeader title="Overview" description="Everything you need to connect your app to this instance." />
      <Card title="Connection details" help="quickstart" description="The publishable key and URL are safe to use in your frontend code.">
        <div className="space-y-4">
          <CodeBlock label="Publishable key" value={inst.publishableKey} />
          <CodeBlock label="Frontend API URL" value={inst.frontendApi} />
        </div>
      </Card>
      <Card title="Environment variables" description="Paste this into .env.local. Replace sk_... with a secret key from the API keys tab. Keep it on the server only.">
        <CodeBlock value={env} />
        <p className="mt-3 text-sm">
          New here? Follow the <Link href="/docs/quickstart" className="font-medium underline decoration-dawn decoration-2 underline-offset-4">quickstart</Link>.
        </p>
      </Card>
      <Card tone="danger" title="Danger zone" description="Deleting an instance permanently removes its users, sessions, keys and webhooks. This can't be undone.">
        <ActionForm action={deleteInstanceAction} submit="Delete this instance" tone="danger" className="max-w-md space-y-3">
          <input type="hidden" name="instanceId" value={inst.id} />
          <Field label={`Type "${inst.name}" to confirm`}>
            <input name="confirmName" required autoComplete="off" className={inputCls} />
          </Field>
        </ActionForm>
      </Card>
    </div>
  );
}
