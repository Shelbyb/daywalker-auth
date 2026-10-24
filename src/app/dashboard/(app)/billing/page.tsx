import { requireUser } from "../guard";
import { ensureAccount } from "@/lib/dashboard";
import { billingEnabled, listPlans, planForAccount } from "@/lib/plans";
import { ActionForm } from "../forms";
import { Badge, Card, PageHeader } from "../ui";
import { billingPortalAction, checkoutAction } from "../actions";

export const metadata = { title: "Billing" };

const price = (c: number, i: string) => (c === 0 ? "Free" : `$${(c / 100).toFixed(c % 100 ? 2 : 0)} / ${i}`);

export default async function BillingPage() {
  const { userId } = await requireUser("/dashboard/billing");
  const accountId = await ensureAccount(userId);
  const [{ plan, subscription }, plans] = await Promise.all([planForAccount(accountId), listPlans()]);
  const enabled = billingEnabled();
  return (
    <div className="space-y-6">
      <PageHeader title="Billing" description="Your plan covers all of your instances." />
      <Card title="Current plan" description={<>{plan?.name ?? "Free"} {subscription?.currentPeriodEnd && <Badge>renews {subscription.currentPeriodEnd.toLocaleDateString("en-US")}</Badge>}</>}>
        {subscription?.stripeCustomerId && enabled && <ActionForm action={billingPortalAction} submit="Manage subscription and invoices" />}
      </Card>
      <div className="grid gap-4 sm:grid-cols-3">
        {plans.map((p) => (
          <Card key={p.id} title={p.name} description={p.description}>
            <p className="text-lg font-semibold">{price(p.priceCents, p.interval)}</p>
            {p.id === plan?.id ? <Badge tone="good">Current plan</Badge> : p.priceCents > 0 && p.stripePriceId && enabled ? (
              <ActionForm action={checkoutAction} submit={`Upgrade to ${p.name}`} className="mt-3"><input type="hidden" name="planId" value={p.id} /></ActionForm>
            ) : null}
          </Card>
        ))}
      </div>
    </div>
  );
}
