import { requirePlatformPage } from "../../guard";
import { ActionForm } from "../../forms";
import { Badge, Card, Field, PageHeader, Toggle } from "../../ui";
import { inputCls } from "../../styles";
import { PLAN_FEATURES, listPlans, type PlanFeature } from "@/lib/plans";
import { deletePlanAction, savePlanAction } from "../actions";

export const metadata = { title: "Plans" };

type Plan = Awaited<ReturnType<typeof listPlans>>[number];

function PlanForm({ plan }: { plan?: Plan }) {
  return (
    <ActionForm action={savePlanAction} submit={plan ? "Save plan" : "Create plan"} className="space-y-4">
      {plan && <input type="hidden" name="id" value={plan.id} />}
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="Name"><input name="name" required defaultValue={plan?.name} className={inputCls} /></Field>
        <Field label="Slug"><input name="slug" required defaultValue={plan?.slug} className={inputCls} /></Field>
        <Field label="Price (USD)"><input name="price" inputMode="decimal" defaultValue={plan ? plan.priceCents / 100 : 0} className={inputCls} /></Field>
        <Field label="Billed">
          <select name="interval" defaultValue={plan?.interval ?? "month"} className={inputCls}><option value="month">Monthly</option><option value="year">Yearly</option></select>
        </Field>
        <Field label="Stripe price ID" hint="From Stripe Products. Leave blank for the free plan."><input name="stripePriceId" defaultValue={plan?.stripePriceId ?? ""} placeholder="price_…" className={inputCls} /></Field>
        <Field label="Sort order"><input name="sortOrder" inputMode="numeric" defaultValue={plan?.sortOrder ?? 0} className={inputCls} /></Field>
      </div>
      <Field label="Description"><input name="description" defaultValue={plan?.description} className={inputCls} /></Field>
      <fieldset className="space-y-1 text-sm">
        <legend className="font-medium">Included features</legend>
        {(Object.keys(PLAN_FEATURES) as PlanFeature[]).map((f) => (
          <label key={f} className="flex items-center gap-2"><input type="checkbox" name="features" value={f} defaultChecked={plan?.features.includes(f)} /> {PLAN_FEATURES[f]}</label>
        ))}
      </fieldset>
      <Toggle name="active" defaultChecked={plan?.active ?? true} label="Available to sign up" />
    </ActionForm>
  );
}

export default async function PlansPage() {
  await requirePlatformPage("/dashboard/platform/plans", "admin");
  const plans = await listPlans(false);
  return (
    <div className="space-y-6">
      <PageHeader title="Plans" description="Plans developer accounts can subscribe to. The default plan applies to everyone without a subscription. Paid plans need a Stripe price ID and STRIPE_SECRET_KEY / STRIPE_WEBHOOK_SECRET on the server." />
      {plans.map((p) => (
        <Card key={p.id} title={p.name} description={<>{p.isDefault && <Badge tone="good">default</Badge>} {!p.active && <Badge tone="bad">inactive</Badge>}</>}>
          <PlanForm plan={p} />
          {!p.isDefault && (
            <ActionForm action={deletePlanAction} submit="Delete plan" tone="danger" className="mt-3">
              <input type="hidden" name="id" value={p.id} />
            </ActionForm>
          )}
        </Card>
      ))}
      <Card title="New plan"><PlanForm /></Card>
    </div>
  );
}
