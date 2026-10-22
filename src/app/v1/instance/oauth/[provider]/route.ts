import { NextResponse } from "next/server";
import { record } from "@/lib/audit";
import { z } from "zod";
import { handler, errors } from "@/lib/http";
import { instanceFromSecretKey } from "@/lib/auth/instance";
import { isProvider, setProviderConfig, callbackUrl } from "@/lib/auth/oauth";
import { parseSettings } from "@/lib/auth/oauth-providers";

const body = z.object({
  clientId: z.string().trim().min(1).max(256),
  clientSecret: z.string().min(1).max(4096),
  enabled: z.boolean().default(true),
  /** oidc: { issuer, displayName? } · gitlab: { issuer? } · microsoft: { tenant? } · apple: { teamId, keyId } */
  settings: z.record(z.string(), z.unknown()).optional(),
});

/** Backend API: configure a provider. The secret is encrypted and never returned. */
export const PUT = handler(async (req: Request, { params }: { params: Promise<{ provider: string }> }) => {
  const inst = await instanceFromSecretKey(req);
  const { provider } = await params;
  if (!isProvider(provider)) throw errors.notFound("Unknown provider");
  const cfg = body.parse(await req.json());
  const settings = parseSettings(provider, cfg.settings, cfg.clientSecret);
  await setProviderConfig(inst.id, provider, { ...cfg, settings });
  void record(inst.id, "social_provider.saved", { actor: { type: "api" }, target: provider, data: { enabled: cfg.enabled } });
  return NextResponse.json({ provider, enabled: cfg.enabled, clientId: cfg.clientId, settings, redirectUri: callbackUrl(provider) });
});
