"use client";

import { useCallback, useEffect, useState } from "react";
import type { User, SecurityInfo, SessionInfo, AuthClient } from "@daywalker/auth";
import { hostedClient } from "../hosted-client";
import { ProfileSection } from "./profile";
import { PasswordSection } from "./password";
import { TwoFactorSection } from "./two-factor";
import { SessionsSection } from "./sessions";
import { PasskeysSection } from "./passkeys";

const PROVIDER_NAMES: Record<string, string> = { google: "Google", github: "GitHub", microsoft: "Microsoft", apple: "Apple", discord: "Discord", gitlab: "GitLab", oidc: "Single sign-on" };
import { Card, Badge, Button } from "./ui";

export function AccountView({ pk, back }: { pk: string; back?: string }) {
  // Created in an effect: the SDK client needs `window`, which doesn't exist during server rendering.
  const [client, setClient] = useState<AuthClient | null>(null);
  const [user, setUser] = useState<User | null>(null);
  const [security, setSecurity] = useState<SecurityInfo | null>(null);
  const [sessions, setSessions] = useState<SessionInfo[]>([]);

  useEffect(() => setClient(hostedClient(pk)), [pk]);

  const refresh = useCallback(async () => {
    if (!client) return;
    const [sec, sess] = await Promise.all([client.getSecurity(), client.listSessions()]);
    setSecurity(sec);
    setSessions(sess);
    setUser(client.state.user);
  }, [client]);

  useEffect(() => {
    if (!client) return;
    (async () => {
      const st = await client.load();
      if (!st.user) {
        // Not signed in here: sign in first, then come back.
        const self = window.location.href;
        window.location.replace(`/sign-in?pk=${encodeURIComponent(pk)}&redirect_url=${encodeURIComponent(new URL(self).pathname + new URL(self).search)}`);
        return;
      }
      await refresh();
    })();
    return client.subscribe((s) => setUser(s.user));
  }, [client, pk, refresh]);

  if (!client || !user || !security)
    return (
      <div className="space-y-4" aria-busy="true">
        {[0, 1, 2].map((i) => <div key={i} className="h-40 animate-pulse rounded-2xl bg-white" />)}
      </div>
    );

  const email = user.emailAddresses.find((e) => e.primary) ?? user.emailAddresses[0];

  return (
    <div className="space-y-6">
      <ProfileSection pk={pk} user={user} />

      <Card title="Email address">
        <div className="flex items-center justify-between gap-3">
          <span className="text-sm">{email?.email}</span>
          {email?.verified ? <Badge tone="good">Verified</Badge> : <Badge tone="warn">Not verified</Badge>}
        </div>
      </Card>

      <PasswordSection pk={pk} hasPassword={security.hasPassword} onChanged={refresh} />
      <PasskeysSection pk={pk} />
      <TwoFactorSection pk={pk} security={security} onChanged={refresh} />

      {security.connectedAccounts.length > 0 && (
        <Card title="Connected accounts" description="Ways you can sign in besides your password.">
          <ul className="divide-y divide-stone-100">
            {security.connectedAccounts.map((a) => (
              <li key={a.provider} className="flex items-center justify-between py-2 text-sm">
                <span>{PROVIDER_NAMES[a.provider] ?? a.provider}</span>
                <span className="text-stone-400">Connected {new Date(a.createdAt).toLocaleDateString()}</span>
              </li>
            ))}
          </ul>
        </Card>
      )}

      <SessionsSection pk={pk} sessions={sessions} onChanged={refresh} />

      <div className="flex justify-end">
        <Button
          variant="secondary"
          onClick={async () => {
            const to = back ?? `/sign-in?pk=${encodeURIComponent(pk)}`;
            const { redirecting } = await client.signOut({ redirectUrl: back ?? undefined });
            if (!redirecting) window.location.assign(to);
          }}
        >
          Sign out
        </Button>
      </div>
    </div>
  );
}
