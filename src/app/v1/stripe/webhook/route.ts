import { NextResponse } from "next/server";
import { handler, errors } from "@/lib/http";
import { env } from "@/lib/env";
import { handleStripeEvent, verifyStripeSignature } from "@/lib/plans";

/** Stripe webhook: signature-checked over the raw body, then updates the account's subscription. */
export const POST = handler(async (req: Request) => {
  const secret = env().STRIPE_WEBHOOK_SECRET;
  if (!secret) throw errors.notFound();
  const raw = await req.text();
  if (raw.length > 1_000_000 || !verifyStripeSignature(raw, req.headers.get("stripe-signature"), secret)) throw errors.badRequest("invalid_signature", "Bad signature");
  await handleStripeEvent(JSON.parse(raw));
  return NextResponse.json({ received: true });
});
