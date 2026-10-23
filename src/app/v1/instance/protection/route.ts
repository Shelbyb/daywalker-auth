import { NextResponse } from "next/server";
import { record } from "@/lib/audit";
import { handler } from "@/lib/http";
import { instanceFromSecretKey } from "@/lib/auth/instance";
import { protectionView, updateProtection } from "@/lib/auth/instance-policy";

/** Backend API: sign-up rules, the human check (Turnstile) and the two-factor requirement. The Turnstile secret is never returned. */
export const GET = handler(async (req: Request) => NextResponse.json(protectionView(await instanceFromSecretKey(req))));

export const PATCH = handler(async (req: Request) => {
  const inst = await instanceFromSecretKey(req);
  const view = await updateProtection(inst, await req.json());
  void record(inst.id, "instance.settings_updated", { actor: { type: "api" }, data: { protection: { ...view, captcha: view.captcha ? { siteKey: view.captcha.siteKey } : null } } });
  return NextResponse.json(view);
});
