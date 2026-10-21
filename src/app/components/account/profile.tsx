"use client";

import type { User } from "@daywalker/auth";
import { hostedClient } from "../hosted-client";
import { Card, Field, Button, Notice, useAction } from "./ui";

export function ProfileSection({ pk, user }: { pk: string; user: User }) {
  const a = useAction();
  return (
    <Card title="Profile">
      <form
        className="space-y-4"
        onSubmit={(e) => {
          e.preventDefault();
          const f = new FormData(e.currentTarget);
          a.run(async () => {
            await hostedClient(pk).updateProfile({ firstName: (f.get("firstName") as string) || null, lastName: (f.get("lastName") as string) || null });
            return "Profile saved";
          });
        }}
      >
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="First name" name="firstName" defaultValue={user.firstName ?? ""} autoComplete="given-name" maxLength={100} />
          <Field label="Last name" name="lastName" defaultValue={user.lastName ?? ""} autoComplete="family-name" maxLength={100} />
        </div>
        {a.error && <Notice tone="error">{a.error}</Notice>}
        {a.ok && <Notice tone="success">{a.ok}</Notice>}
        <Button disabled={a.busy}>{a.busy ? "Saving…" : "Save"}</Button>
      </form>
    </Card>
  );
}
