import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { resolveSession, endSession, BIND_WINDOW_MS } from "@/lib/auth/sessions";
import { getUser } from "@/lib/auth/users";
import { safeRedirect } from "@/lib/auth/redirect";
import { sessionSettings } from "@/lib/session-settings";
import { startSingleLogout } from "@/lib/auth/saml-logout";

export const OPTIONS = preflight;

/** Current session + user, or { session: null }. */
export const GET = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  const s = ctx.refreshToken ? await resolveSession(ctx.inst.id, ctx.refreshToken) : null;
  if (!s) return ctx.json({ session: null, user: null });
  return ctx.json({ session: { id: s.id, expiresAt: s.expiresAt, deviceBound: !!s.dpopJkt, deviceBindable: !s.dpopJkt && !!s.createdAt && Date.now() - new Date(s.createdAt).getTime() <= BIND_WINDOW_MS, deviceBinding: sessionSettings(ctx.inst).deviceBinding }, user: await getUser(ctx.inst.id, s.userId) });
});

/**
 * Sign out. If the session came from an SSO connection with single logout on, also returns
 * `ssoLogoutUrl`: send the browser there to sign out at the identity provider too. It comes back
 * to `redirectUrl` (relative path or an allowed origin) or the hosted sign-in page.
 */
export const DELETE = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  let ssoLogoutUrl: string | null = null;
  if (ctx.refreshToken) {
    const body = (await req.json().catch(() => null)) as { redirectUrl?: unknown } | null;
    const redirect = typeof body?.redirectUrl === "string" ? safeRedirect(body.redirectUrl.slice(0, 2000), ctx.inst.allowedOrigins) : null;
    ssoLogoutUrl = await startSingleLogout(ctx.inst.id, ctx.refreshToken, redirect).catch(() => null);
    await endSession(ctx.inst.id, ctx.refreshToken);
  }
  return ctx.clearRefreshCookie(ctx.json({ ok: true, ...(ssoLogoutUrl ? { ssoLogoutUrl } : {}) }));
});
