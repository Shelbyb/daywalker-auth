import Link from "next/link";
import { templatesFor } from "@/lib/dashboard";
import { SAMPLE_VARS, renderTemplate } from "@/lib/email-templates";
import { requireUser } from "../../../guard";
import { accentColorAction, resetTemplateAction, saveTemplateAction, testTemplateAction } from "../../../actions";
import { ActionForm, ConfirmAction } from "../../../forms";
import { Badge, Card, Field, PageHeader } from "../../../ui";
import { inputCls } from "../../../styles";
import { guarded } from "../../../server";

export const metadata = { title: "Emails" };

export default async function EmailsPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const { userId } = await requireUser(`/dashboard/instances/${encodeURIComponent(id)}/emails`);
  const { templates, accentColor, appName } = await guarded(() => templatesFor(userId, id));
  const sample = SAMPLE_VARS(appName);
  return (
    <div className="space-y-6">
      <PageHeader
        title="Emails"
        description={<>Change the wording of the emails your users get. Write plain text and use the placeholders listed under each email; we build a clean HTML version and escape everything you type. See the <Link href="/docs/guides/email-templates" className="font-medium underline decoration-dawn decoration-2 underline-offset-4">guide</Link>.</>}
      />
      <Card title="Brand color" description="Used for buttons and links in every email.">
        <ActionForm action={accentColorAction} submit="Save color" className="flex flex-wrap items-end gap-3">
          <input type="hidden" name="instanceId" value={id} />
          <Field label="Color">
            <input type="color" name="accentColor" defaultValue={accentColor ?? "#14121a"} className="h-10 w-20 cursor-pointer rounded-lg border border-stone-300 bg-white p-1" />
          </Field>
        </ActionForm>
        {accentColor && (
          <div className="mt-3">
            <ActionForm action={accentColorAction} submit="Use the default color" tone="ghost">
              <input type="hidden" name="instanceId" value={id} />
              <input type="hidden" name="reset" value="1" />
            </ActionForm>
          </div>
        )}
      </Card>
      {templates.map((t) => {
        const preview = renderTemplate({ subject: t.subject, body: t.body }, { ...sample, link_label: t.kind === "invitation" ? "Accept invitation" : t.kind === "sign_in" ? `Sign in to ${appName}` : "Open link" }, accentColor ?? undefined);
        return (
          <Card key={t.kind}>
            <div className="flex flex-wrap items-center gap-2">
              <h2 className="text-base font-semibold">{t.label}</h2>
              {t.custom ? <Badge tone="good">custom</Badge> : <Badge>default</Badge>}
            </div>
            <div className="mt-4 grid gap-6 lg:grid-cols-2">
              <ActionForm action={saveTemplateAction} submit="Save" className="space-y-4">
                <input type="hidden" name="instanceId" value={id} />
                <input type="hidden" name="kind" value={t.kind} />
                <Field label="Subject">
                  <input name="subject" required maxLength={200} defaultValue={t.subject} className={inputCls} />
                </Field>
                <Field
                  label="Body"
                  hint={<>Placeholders: {t.vars.map((v) => <code key={v} className="mr-1 rounded bg-stone-100 px-1">{`{{${v}}}`}</code>)}. Required: {t.required.map((v) => <code key={v} className="mr-1 rounded bg-stone-100 px-1">{`{{${v}}}`}</code>)}. Put {"{{code}}"} or {"{{link}}"} on a line of its own to show it as a big code or a button.</>}
                >
                  <textarea name="body" required maxLength={5000} rows={9} defaultValue={t.body} className={`${inputCls} font-mono text-xs`} />
                </Field>
              </ActionForm>
              <div>
                <p className="mb-1 text-sm font-medium text-stone-700">Preview (saved version, sample values)</p>
                <div className="rounded-lg border border-stone-200 bg-stone-50">
                  <p className="border-b border-stone-200 px-3 py-2 text-sm"><span className="text-stone-500">Subject:</span> {preview.subject}</p>
                  {/* Our own renderer's output: every piece of developer text and every value is escaped. */}
                  <div className="bg-white text-sm" dangerouslySetInnerHTML={{ __html: preview.html }} />
                </div>
                <div className="mt-3 flex flex-wrap gap-2">
                  <ActionForm action={testTemplateAction} submit="Send me a test" tone="ghost">
                    <input type="hidden" name="instanceId" value={id} />
                    <input type="hidden" name="kind" value={t.kind} />
                  </ActionForm>
                  {t.custom && (
                    <ConfirmAction action={resetTemplateAction} label="Reset to default" confirmLabel="Yes, reset" prompt="Replace your wording with the default?">
                      <input type="hidden" name="instanceId" value={id} />
                      <input type="hidden" name="kind" value={t.kind} />
                    </ConfirmAction>
                  )}
                </div>
              </div>
            </div>
          </Card>
        );
      })}
    </div>
  );
}
