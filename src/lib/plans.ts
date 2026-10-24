/** Plans, feature gating and Stripe billing (plain REST + HMAC, no SDK). Plans belong to developer accounts. */
import { createHmac, timingSafeEqual } from "node:crypto";
import { asc, eq } from "drizzle-orm";
import { db, schema } from "./db";
import { env } from "./env";
import { errors } from "./http";
import { newId } from "./ids";

/** Features a plan can include. Anything not listed is free for everyone. */
export const PLAN_FEATURES = {
  session_customization: "Session customization (custom claims, inactivity timeout)",
  organization_settings: "Organization settings",
  custom_domain: "Custom domain for the Account Portal",
} as const;
export type PlanFeature = keyof typeof PLAN_FEATURES;

export const listPlans = (activeOnly = true) =>
  db().select().from(schema.plans).where(activeOnly ? eq(schema.plans.active, true) : undefined).orderBy(asc(schema.plans.sortOrder), asc(schema.plans.priceCents));

export async function defaultPlan() {
  const [p] = await db().select().from(schema.plans).where(eq(schema.plans.isDefault, true)).limit(1);
  return p ?? null;
}

/** The plan an account is on; the default (free) plan when it has no live subscription. */
export async function planForAccount(accountId: string) {
  const [row] = await db().select({ p: schema.plans, s: schema.subscriptions }).from(schema.subscriptions).innerJoin(schema.plans, eq(schema.plans.id, schema.subscriptions.planId)).where(eq(schema.subscriptions.accountId, accountId)).limit(1);
  if (row && ["active", "trialing", "past_due"].includes(row.s.status)) return { plan: row.p, subscription: row.s };
  return { plan: await defaultPlan(), subscription: row?.s ?? null };
}

export async function planAllows(accountId: string, feature: PlanFeature) {
  const { plan } = await planForAccount(accountId);
  return !!plan?.features.includes(feature);
}

/** Throws a 403 telling the developer which plan unlocks the feature. */
export async function requireFeature(accountId: string, feature: PlanFeature) {
  if (await planAllows(accountId, feature)) return;
  const plans = await listPlans();
  const need = plans.find((p) => p.features.includes(feature));
  throw errors.forbidden(`${PLAN_FEATURES[feature]} needs the ${need?.name ?? "paid"} plan. Upgrade under Billing.`);
}

/** Cheapest active plan that includes the feature (for badges). */
export async function planNeeded(feature: PlanFeature) {
  return (await listPlans()).find((p) => p.features.includes(feature) && p.priceCents > 0) ?? null;
}

// ---------- Admin ----------
export async function savePlan(input: { id?: string; name: string; slug: string; description: string; priceCents: number; interval: string; stripePriceId: string; features: string[]; active: boolean; sortOrder: number }) {
  const name = input.name.trim().slice(0, 60);
  const slug = input.slug.trim().toLowerCase();
  if (!name || !/^[a-z0-9-]{1,30}$/.test(slug)) throw errors.badRequest("invalid_request", "Name and a slug of letters, digits and dashes are required");
  if (!Number.isInteger(input.priceCents) || input.priceCents < 0 || input.priceCents > 10_000_00) throw errors.badRequest("invalid_request", "Price must be 0 to 10000 dollars");
  if (!["month", "year"].includes(input.interval)) throw errors.badRequest("invalid_request", "Interval must be month or year");
  const features = input.features.filter((f) => f in PLAN_FEATURES);
  const stripePriceId = input.stripePriceId.trim() || null;
  if (stripePriceId && !/^price_[A-Za-z0-9]+$/.test(stripePriceId)) throw errors.badRequest("invalid_request", "Stripe price ID looks like price_…");
  const row = { slug, name, description: input.description.trim().slice(0, 300), priceCents: input.priceCents, interval: input.interval, stripePriceId, features, active: input.active, sortOrder: input.sortOrder };
  if (input.id) {
    const [cur] = await db().select().from(schema.plans).where(eq(schema.plans.id, input.id)).limit(1);
    if (!cur) throw errors.notFound();
    await db().update(schema.plans).set({ ...row, active: cur.isDefault ? true : row.active }).where(eq(schema.plans.id, input.id));
    return input.id;
  }
  const id = newId("plan");
  await db().insert(schema.plans).values({ id, ...row });
  return id;
}

export async function deletePlan(id: string) {
  const [cur] = await db().select().from(schema.plans).where(eq(schema.plans.id, id)).limit(1);
  if (!cur) throw errors.notFound();
  if (cur.isDefault) throw errors.badRequest("invalid_request", "The default plan can't be deleted");
  const [used] = await db().select({ a: schema.subscriptions.accountId }).from(schema.subscriptions).where(eq(schema.subscriptions.planId, id)).limit(1);
  if (used) throw errors.badRequest("invalid_request", "Accounts are subscribed to this plan. Deactivate it instead.");
  await db().delete(schema.plans).where(eq(schema.plans.id, id));
}

// ---------- Stripe ----------
export const billingEnabled = () => !!env().STRIPE_SECRET_KEY;

async function stripe<T>(path: string, params: Record<string, string>): Promise<T> {
  const r = await fetch(`https://api.stripe.com/v1/${path}`, {
    method: "POST",
    headers: { authorization: `Bearer ${env().STRIPE_SECRET_KEY}`, "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(params),
    signal: AbortSignal.timeout(10_000),
  });
  if (!r.ok) throw errors.badRequest("invalid_request", "Billing provider error. Try again later.");
  return (await r.json()) as T;
}

export async function startCheckout(accountId: string, planId: string) {
  if (!billingEnabled()) throw errors.badRequest("invalid_request", "Billing isn't configured");
  const [plan] = await db().select().from(schema.plans).where(eq(schema.plans.id, planId)).limit(1);
  if (!plan || !plan.active || !plan.stripePriceId) throw errors.badRequest("invalid_request", "This plan can't be purchased");
  const base = env().APP_URL;
  const s = await stripe<{ url: string }>("checkout/sessions", {
    mode: "subscription",
    "line_items[0][price]": plan.stripePriceId,
    "line_items[0][quantity]": "1",
    client_reference_id: accountId,
    "metadata[account_id]": accountId,
    "metadata[plan_id]": plan.id,
    "subscription_data[metadata][account_id]": accountId,
    "subscription_data[metadata][plan_id]": plan.id,
    success_url: `${base}/dashboard/billing?status=success`,
    cancel_url: `${base}/dashboard/billing?status=cancelled`,
  });
  return s.url;
}

export async function billingPortalUrl(accountId: string) {
  const { subscription } = await planForAccount(accountId);
  if (!billingEnabled() || !subscription?.stripeCustomerId) throw errors.badRequest("invalid_request", "No billing account yet");
  const s = await stripe<{ url: string }>("billing_portal/sessions", { customer: subscription.stripeCustomerId, return_url: `${env().APP_URL}/dashboard/billing` });
  return s.url;
}

/** Verifies the `Stripe-Signature` header (t=…,v1=…) over the raw body; 5 minute tolerance. */
export function verifyStripeSignature(raw: string, header: string | null, secret: string, now = Date.now()) {
  if (!header) return false;
  const parts = Object.fromEntries(header.split(",").map((p) => p.split("=") as [string, string]));
  const t = Number(parts.t);
  if (!t || Math.abs(now / 1000 - t) > 300) return false;
  const want = createHmac("sha256", secret).update(`${t}.${raw}`).digest();
  return header.split(",").filter((p) => p.startsWith("v1=")).some((p) => {
    const got = Buffer.from(p.slice(3), "hex");
    return got.length === want.length && timingSafeEqual(got, want);
  });
}

type StripeEvent = { type: string; data: { object: Record<string, any> } };

export async function handleStripeEvent(ev: StripeEvent) {
  const o = ev.data.object;
  const accountId: string | undefined = o.metadata?.account_id ?? o.client_reference_id;
  if (!accountId) return;
  const [acct] = await db().select({ id: schema.accounts.id }).from(schema.accounts).where(eq(schema.accounts.id, accountId)).limit(1);
  if (!acct) return;
  if (ev.type === "checkout.session.completed") {
    const planId = o.metadata?.plan_id;
    const [plan] = planId ? await db().select().from(schema.plans).where(eq(schema.plans.id, planId)).limit(1) : [];
    if (!plan) return;
    await upsertSub(accountId, { planId: plan.id, stripeCustomerId: o.customer ?? null, stripeSubscriptionId: o.subscription ?? null, status: "active" });
  } else if (ev.type === "customer.subscription.updated" || ev.type === "customer.subscription.deleted") {
    const dead = ev.type.endsWith("deleted");
    const fallback = await defaultPlan();
    const priceId = o.items?.data?.[0]?.price?.id;
    const [byPrice] = priceId ? await db().select().from(schema.plans).where(eq(schema.plans.stripePriceId, priceId)).limit(1) : [];
    const planId = dead ? fallback?.id : (byPrice?.id ?? o.metadata?.plan_id);
    if (!planId) return;
    await upsertSub(accountId, {
      planId, stripeCustomerId: o.customer ?? null, stripeSubscriptionId: dead ? null : (o.id ?? null),
      status: dead ? "active" : String(o.status ?? "active"),
      currentPeriodEnd: o.current_period_end ? new Date(o.current_period_end * 1000) : null,
    });
  }
}

async function upsertSub(accountId: string, v: { planId: string; stripeCustomerId: string | null; stripeSubscriptionId: string | null; status: string; currentPeriodEnd?: Date | null }) {
  const set = { ...v, updatedAt: new Date() };
  await db().insert(schema.subscriptions).values({ accountId, ...set }).onConflictDoUpdate({ target: schema.subscriptions.accountId, set });
}
