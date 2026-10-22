import { NextResponse } from "next/server";
import { record } from "@/lib/audit";
import { z } from "zod";
import { handler, errors } from "@/lib/http";
import { instanceFromSecretKey } from "@/lib/auth/instance";
import { isProvider, setProviderConfig, callbackUrl } from "@/lib/auth/oauth";

const body = z.object({
  clientId: z.string().trim().min(1).max(256),
  clientSecret: z.string().min(1).max(512),
  enabled: z.boolean().default(true),
});

/** Backend API: configure a provider. The secret is encrypted and never returned. */
export const PUT = handler(async (req: Request, { params }: { params: Promise<{ provider: string }> }) => {
  const inst = await instanceFromSecretKey(req);
  const { provider } = await params;
  if (!isProvider(provider)) throw errors.notFound("Unknown provider");
  const cfg = body.parse(await req.json());
  await setProviderConfig(inst.id, provider, cfg);
  void record(inst.id, "social_provider.saved", { actor: { type: "api" }, target: provider, data: { enabled: cfg.enabled } });
  return NextResponse.json({ provider, enabled: cfg.enabled, clientId: cfg.clientId, redirectUri: callbackUrl(provider) });
});
