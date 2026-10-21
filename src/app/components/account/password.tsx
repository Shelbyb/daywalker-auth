"use client";

import { useState } from "react";
import { hostedClient } from "../hosted-client";
import { Card, Field, Button, Notice, useAction } from "./ui";

export function PasswordSection({ pk, hasPassword, onChanged }: { pk: string; hasPassword: boolean; onChanged: () => void }) {
  const a = useAction();
  const [open, setOpen] = useState(false);

  if (!hasPassword)
    return (
      <Card title="Password" description="You sign in with a connected account, so there's no password yet.">
        <a href={`/forgot-password?pk=${encodeURIComponent(pk)}`} className="text-sm font-medium underline-offset-4 hover:underline">Set a password</a>
      </Card>
    );

  return (
    <Card title="Password" description="Changing your password signs you out on all other devices.">
      {!open ? (
        <Button variant="secondary" onClick={() => setOpen(true)}>Change password</Button>
      ) : (
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            const form = e.currentTarget;
            const f = new FormData(form);
            if (f.get("newPassword") !== f.get("confirm")) return a.run(async () => { throw new Error("The new passwords don't match"); });
            a.run(async () => {
              const r = await hostedClient(pk).changePassword({ currentPassword: f.get("currentPassword") as string, newPassword: f.get("newPassword") as string });
              form.reset();
              setOpen(false);
              onChanged();
              return r.otherSessionsSignedOut ? `Password changed. Signed out ${r.otherSessionsSignedOut} other session(s).` : "Password changed.";
            });
          }}
        >
          <Field label="Current password" name="currentPassword" type="password" autoComplete="current-password" required maxLength={256} />
          <Field label="New password" name="newPassword" type="password" autoComplete="new-password" required maxLength={256} />
          <Field label="Confirm new password" name="confirm" type="password" autoComplete="new-password" required maxLength={256} />
          {a.error && <Notice tone="error">{a.error}</Notice>}
          <div className="flex gap-2">
            <Button disabled={a.busy}>{a.busy ? "Saving…" : "Update password"}</Button>
            <Button type="button" variant="secondary" onClick={() => setOpen(false)}>Cancel</Button>
          </div>
        </form>
      )}
      {a.ok && !open && <div className="mt-3"><Notice tone="success">{a.ok}</Notice></div>}
    </Card>
  );
}
