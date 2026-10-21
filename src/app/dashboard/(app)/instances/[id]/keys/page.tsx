import { Suspense } from "react";
import { listKeys } from "@/lib/dashboard";
import { requireUser } from "../../../guard";
import { createKeyAction, revokeKeyAction } from "../../../actions";
import { ActionForm, ConfirmAction } from "../../../forms";
import { Card, EmptyState, Field, PageHeader, Skeleton, inputCls } from "../../../ui";
import { fmtDate, guarded } from "../../../server";

export const metadata = { title: "API keys" };

async function Keys({ userId, id }: { userId: string; id: string }) {
  const keys = await guarded(() => listKeys(userId, id));
  if (!keys.length) return <EmptyState title="No active keys">Create a key below to call the backend API from your server.</EmptyState>;
  return (
    <div className="overflow-x-auto rounded-xl border border-stone-200 bg-white">
      <table className="w-full min-w-[34rem] text-left text-sm">
        <thead className="border-b border-stone-200 text-xs uppercase text-stone-500">
          <tr><th className="p-3">Name</th><th className="p-3">Key</th><th className="p-3">Last used</th><th className="p-3">Created</th><th className="p-3"><span className="sr-only">Actions</span></th></tr>
        </thead>
        <tbody>
          {keys.map((k) => (
            <tr key={k.id} className="border-b border-stone-100 last:border-0 align-top">
              <td className="p-3 font-medium">{k.name}</td>
              <td className="p-3 font-mono text-xs">{k.prefix}…</td>
              <td className="p-3 text-stone-600">{fmtDate(k.lastUsedAt)}</td>
              <td className="p-3 text-stone-600">{fmtDate(k.createdAt)}</td>
              <td className="p-3">
                <ConfirmAction action={revokeKeyAction} label="Revoke" confirmLabel="Yes, revoke" prompt={`Revoke "${k.name}"? Anything using it stops working immediately.`}>
                  <input type="hidden" name="instanceId" value={id} />
                  <input type="hidden" name="keyId" value={k.id} />
                </ConfirmAction>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default async function KeysPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const { userId } = await requireUser(`/dashboard/instances/${encodeURIComponent(id)}/keys`);
  return (
    <div className="space-y-6">
      <PageHeader title="API keys" description="Secret keys let your server call the backend API. Keep them private: never put one in frontend code." />
      <Suspense fallback={<Skeleton />}>
        <Keys userId={userId} id={id} />
      </Suspense>
      <Card title="Create a key" description="The full key is shown once, right after you create it. We only store a fingerprint.">
        <ActionForm action={createKeyAction} submit="Create key" resetOnSuccess secretLabel="New secret key" className="max-w-md space-y-4">
          <input type="hidden" name="instanceId" value={id} />
          <Field label="Name" hint="Something that tells you where it's used, like “Production server”.">
            <input name="name" required maxLength={60} autoComplete="off" className={inputCls} />
          </Field>
        </ActionForm>
      </Card>
    </div>
  );
}
