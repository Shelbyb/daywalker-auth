import { Suspense } from "react";
import Link from "next/link";
import { ownedInstance } from "@/lib/dashboard";
import { EVENT_TYPES, listDeliveries, listEndpoints } from "@/lib/webhooks";
import { requireUser } from "../../../guard";
import {
  createWebhookAction, deleteWebhookAction, retryDeliveryAction, rotateWebhookSecretAction, sendTestWebhookAction, toggleWebhookAction,
} from "../../../actions";
import { ActionForm, ConfirmAction } from "../../../forms";
import { Badge, Card, EmptyState, Field, PageHeader, Skeleton } from "../../../ui";
import { inputCls } from "../../../styles";
import { fmtDateTime, guarded } from "../../../server";

export const metadata = { title: "Webhooks" };

const SELECTABLE = EVENT_TYPES.filter((e) => e !== "webhook.test");
const statusTone = { succeeded: "good", failed: "bad", pending: "warn" } as const;

async function Deliveries({ id, endpointId }: { id: string; endpointId: string }) {
  const rows = await listDeliveries(id, endpointId, 10);
  if (!rows.length) return <p className="text-sm text-stone-500">No deliveries yet. Send a test event to see one here.</p>;
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[42rem] text-left text-xs">
        <thead className="text-stone-500">
          <tr><th className="py-1.5 pr-3">Event</th><th className="pr-3">Status</th><th className="pr-3">Attempts</th><th className="pr-3">Last error</th><th className="pr-3">Next retry</th><th className="pr-3">Created</th><th><span className="sr-only">Actions</span></th></tr>
        </thead>
        <tbody>
          {rows.map((d) => (
            <tr key={d.id} className="border-t border-stone-100 align-top">
              <td className="py-1.5 pr-3 font-mono">{d.eventType}</td>
              <td className="pr-3"><Badge tone={statusTone[d.status as keyof typeof statusTone] ?? "neutral"}>{d.status}</Badge></td>
              <td className="pr-3">{d.attempts}</td>
              <td className="max-w-[14rem] break-words pr-3 text-stone-600">{d.lastError ?? "-"}</td>
              <td className="pr-3 text-stone-600">{d.nextAttemptAt ? fmtDateTime(d.nextAttemptAt) : "-"}</td>
              <td className="pr-3 text-stone-600">{fmtDateTime(d.createdAt)}</td>
              <td>
                {d.status !== "pending" && (
                  <ActionForm action={retryDeliveryAction} submit="Retry" tone="ghost" className="space-y-1">
                    <input type="hidden" name="instanceId" value={id} />
                    <input type="hidden" name="deliveryId" value={d.id} />
                  </ActionForm>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

async function Endpoints({ userId, id }: { userId: string; id: string }) {
  await guarded(() => ownedInstance(userId, id));
  const endpoints = await listEndpoints(id);
  if (!endpoints.length) return <EmptyState title="No endpoints yet">Add one below and we&apos;ll start sending events to it.</EmptyState>;
  return (
    <ul className="space-y-4">
      {endpoints.map((e) => (
        <li key={e.id}>
          <Card>
            <div className="flex flex-wrap items-center gap-2">
              <code className="min-w-0 break-all font-mono text-sm font-medium">{e.url}</code>
              {e.enabled ? <Badge tone="good">Enabled</Badge> : <Badge>Disabled</Badge>}
            </div>
            {e.description && <p className="mt-1 text-sm text-stone-600">{e.description}</p>}
            <p className="mt-2 text-xs text-stone-600">
              Events: {e.events.includes("*") ? "All events" : e.events.join(", ")}
            </p>
            <div className="mt-3 flex flex-wrap items-start gap-2">
              <ActionForm action={toggleWebhookAction} submit={e.enabled ? "Disable" : "Enable"} tone="ghost" className="space-y-1">
                <input type="hidden" name="instanceId" value={id} />
                <input type="hidden" name="endpointId" value={e.id} />
                <input type="hidden" name="enabled" value={e.enabled ? "false" : "true"} />
              </ActionForm>
              <ActionForm action={sendTestWebhookAction} submit="Send test" tone="ghost" className="space-y-1">
                <input type="hidden" name="instanceId" value={id} />
                <input type="hidden" name="endpointId" value={e.id} />
              </ActionForm>
              <ConfirmAction action={rotateWebhookSecretAction} tone="ghost" label="Rotate secret" confirmLabel="Yes, rotate" secretLabel="New signing secret" prompt="Create a new signing secret? The old one stops working right away, so update your receiver.">
                <input type="hidden" name="instanceId" value={id} />
                <input type="hidden" name="endpointId" value={e.id} />
              </ConfirmAction>
              <ConfirmAction action={deleteWebhookAction} label="Delete" confirmLabel="Yes, delete" prompt="Delete this endpoint and its delivery history?">
                <input type="hidden" name="instanceId" value={id} />
                <input type="hidden" name="endpointId" value={e.id} />
              </ConfirmAction>
            </div>
            <h3 className="mt-5 text-sm font-semibold">Recent deliveries</h3>
            <div className="mt-2">
              <Suspense fallback={<Skeleton lines={2} />}>
                <Deliveries id={id} endpointId={e.id} />
              </Suspense>
            </div>
          </Card>
        </li>
      ))}
    </ul>
  );
}

export default async function WebhooksPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const { userId } = await requireUser(`/dashboard/instances/${encodeURIComponent(id)}/webhooks`);
  return (
    <div className="space-y-6">
      <PageHeader
        title="Webhooks"
        description={<>We send an HTTPS request to your server when something happens, like a new user signing up. Each request is signed with the endpoint&apos;s secret so you can verify it came from us. <Link href="/docs/guides/webhooks" className="font-medium underline decoration-dawn decoration-2 underline-offset-4">Read the guide</Link>.</>}
      />
      <Suspense fallback={<Skeleton lines={4} />}>
        <Endpoints userId={userId} id={id} />
      </Suspense>
      <Card title="Add an endpoint" description="Use a public https URL. The signing secret is shown once.">
        <ActionForm action={createWebhookAction} submit="Create endpoint" resetOnSuccess secretLabel="Signing secret" className="max-w-xl space-y-4">
          <input type="hidden" name="instanceId" value={id} />
          <Field label="Endpoint URL">
            <input name="url" type="url" required placeholder="https://example.com/webhooks/daywalker" className={inputCls} />
          </Field>
          <Field label="Description (optional)">
            <input name="description" maxLength={200} className={inputCls} />
          </Field>
          <fieldset className="space-y-2">
            <legend className="mb-1 text-sm font-medium text-stone-700">Events</legend>
            <label className="flex items-center gap-2 text-sm font-medium">
              <input type="checkbox" name="allEvents" className="size-4 accent-ink" /> All events
            </label>
            <div className="grid gap-1.5 sm:grid-cols-2">
              {SELECTABLE.map((ev) => (
                <label key={ev} className="flex items-center gap-2 font-mono text-xs">
                  <input type="checkbox" name="events" value={ev} className="size-4 accent-ink" /> {ev}
                </label>
              ))}
            </div>
            <p className="text-xs text-stone-500">If &ldquo;All events&rdquo; is ticked, the individual choices are ignored.</p>
          </fieldset>
        </ActionForm>
      </Card>
    </div>
  );
}
