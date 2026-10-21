"use client";

import type { SessionInfo } from "@daywalker/auth";
import { hostedClient } from "../hosted-client";
import { Card, Button, Badge, Notice, useAction } from "./ui";

const rel = (iso: string) => {
  const mins = Math.round((Date.now() - new Date(iso).getTime()) / 60000);
  if (mins < 2) return "Active now";
  if (mins < 60) return `${mins} minutes ago`;
  const h = Math.round(mins / 60);
  return h < 48 ? `${h} hours ago` : new Date(iso).toLocaleDateString();
};

export function SessionsSection({ pk, sessions, onChanged }: { pk: string; sessions: SessionInfo[]; onChanged: () => void }) {
  const client = hostedClient(pk);
  const a = useAction();
  const others = sessions.filter((s) => !s.current).length;

  return (
    <Card title="Where you're signed in" description="Don't recognise a device? Sign it out and change your password.">
      <ul className="divide-y divide-stone-100">
        {sessions.map((s) => (
          <li key={s.id} className="flex items-center justify-between gap-3 py-3">
            <div className="min-w-0">
              <p className="flex items-center gap-2 text-sm font-medium">
                {s.device} {s.current && <Badge tone="good">This device</Badge>}
              </p>
              <p className="text-xs text-stone-500">
                {rel(s.lastActiveAt)}
                {s.ipHint && ` · ${s.ipHint}`}
              </p>
            </div>
            {!s.current && (
              <Button variant="secondary" disabled={a.busy} onClick={() => a.run(async () => { await client.revokeSession(s.id); onChanged(); return "Device signed out."; })}>
                Sign out
              </Button>
            )}
          </li>
        ))}
      </ul>
      {others > 1 && (
        <Button className="mt-4" variant="danger" disabled={a.busy} onClick={() => a.run(async () => { const n = await client.revokeOtherSessions(); onChanged(); return `Signed out ${n} other session(s).`; })}>
          Sign out all other devices
        </Button>
      )}
      {(a.ok || a.error) && <div className="mt-3"><Notice tone={a.error ? "error" : "success"}>{a.error ?? a.ok}</Notice></div>}
    </Card>
  );
}
