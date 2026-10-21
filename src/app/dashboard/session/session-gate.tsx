"use client";

import { useEffect } from "react";
import { createAuthClient } from "@daywalker/auth";

/**
 * The 60-second session token lapsed (or there is none). If the browser still has a refresh
 * cookie, exchange it for a new token (the SDK writes the cookie on this origin) and go back.
 * Otherwise send the person to sign in, then back to the dashboard.
 */
export function SessionGate({ pk, target }: { pk: string; target: string }) {
  useEffect(() => {
    const guard = "dw_dashboard_refresh";
    const origin = window.location.origin;
    const signIn = () => {
      const u = new URL(`${origin}/sign-in`);
      u.searchParams.set("pk", pk);
      u.searchParams.set("redirect_url", `${origin}${target}`);
      window.location.replace(u.toString());
    };
    (async () => {
      // If we refreshed less than 10 seconds ago and the server still says "signed out", stop looping.
      try {
        const last = Number(sessionStorage.getItem(guard) ?? 0);
        if (Date.now() - last < 10_000) {
          sessionStorage.removeItem(guard);
          return signIn();
        }
      } catch {}
      const client = createAuthClient({ publishableKey: pk, frontendApi: origin, syncCookie: true });
      await client.load();
      if (!client.state.sessionId) return signIn();
      try {
        await client.getToken({ force: true });
        try { sessionStorage.setItem(guard, String(Date.now())); } catch {}
        window.location.replace(target);
      } catch {
        signIn();
      }
    })();
  }, [pk, target]);

  return <p className="flex min-h-dvh items-center justify-center text-sm text-stone-500">Signing you in…</p>;
}
