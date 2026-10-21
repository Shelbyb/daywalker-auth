"use client";

import { useEffect, useState } from "react";
import { AuthError, type PasskeyInfo } from "@daywalker/auth";
import { hostedClient } from "../hosted-client";
import { Card, Button, Badge, Notice, Field, useAction } from "./ui";

export function PasskeysSection({ pk }: { pk: string }) {
  const client = hostedClient(pk);
  const a = useAction();
  const [items, setItems] = useState<PasskeyInfo[]>([]);
  const [renaming, setRenaming] = useState<string | null>(null);
  const [needsReauth, setNeedsReauth] = useState(false);
  const supported = client.passkeysSupported();

  const reload = () => client.listPasskeys().then(setItems);
  useEffect(() => { reload(); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const signInAgain = `/sign-in?pk=${encodeURIComponent(pk)}&redirect_url=${encodeURIComponent(`/account?pk=${encodeURIComponent(pk)}`)}`;

  return (
    <Card title="Passkeys" description="Sign in with your fingerprint, face or device PIN. No password to remember or leak.">
      {items.length > 0 && (
        <ul className="mb-4 divide-y divide-stone-100">
          {items.map((p) => (
            <li key={p.id} className="flex items-center justify-between gap-3 py-3">
              {renaming === p.id ? (
                <form
                  className="flex flex-1 items-end gap-2"
                  onSubmit={(e) => {
                    e.preventDefault();
                    const name = new FormData(e.currentTarget).get("name") as string;
                    a.run(async () => { await client.renamePasskey(p.id, name); setRenaming(null); await reload(); });
                  }}
                >
                  <div className="flex-1"><Field label="Name" name="name" defaultValue={p.name} maxLength={60} autoFocus /></div>
                  <Button disabled={a.busy}>Save</Button>
                </form>
              ) : (
                <>
                  <div className="min-w-0">
                    <p className="flex items-center gap-2 text-sm font-medium">
                      {p.name} {p.synced && <Badge>Synced</Badge>}
                    </p>
                    <p className="text-xs text-stone-500">
                      Added {new Date(p.createdAt).toLocaleDateString()}
                      {p.lastUsedAt ? ` · last used ${new Date(p.lastUsedAt).toLocaleDateString()}` : " · never used"}
                    </p>
                  </div>
                  <div className="flex gap-2">
                    <Button variant="secondary" onClick={() => setRenaming(p.id)}>Rename</Button>
                    <Button variant="danger" disabled={a.busy} onClick={() => a.run(async () => { await client.deletePasskey(p.id); await reload(); return "Passkey removed."; })}>
                      Remove
                    </Button>
                  </div>
                </>
              )}
            </li>
          ))}
        </ul>
      )}

      {!supported ? (
        <p className="text-sm text-stone-500">This browser doesn&apos;t support passkeys.</p>
      ) : needsReauth ? (
        <div className="space-y-3">
          <Notice tone="error">For your security, adding a passkey needs a recent sign-in.</Notice>
          <a href={signInAgain} className="text-sm font-medium underline-offset-4 hover:underline">Sign in again to continue</a>
        </div>
      ) : (
        <Button
          disabled={a.busy}
          onClick={() =>
            a.run(async () => {
              try {
                await client.registerPasskey();
              } catch (e) {
                if (e instanceof AuthError && e.code === "reauth_required") return void setNeedsReauth(true);
                if (e instanceof AuthError && e.code === "passkey_cancelled") return;
                throw e;
              }
              await reload();
              return "Passkey added. You can now sign in with it.";
            })
          }
        >
          Add a passkey
        </Button>
      )}
      {(a.ok || a.error) && <div className="mt-3"><Notice tone={a.error ? "error" : "success"}>{a.error ?? a.ok}</Notice></div>}
    </Card>
  );
}
