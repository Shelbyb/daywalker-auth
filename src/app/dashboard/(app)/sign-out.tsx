"use client";

import { useState } from "react";
import { createAuthClient } from "@daywalker/auth";
import { btnCls } from "./ui";

export function SignOutButton({ publishableKey }: { publishableKey: string }) {
  const [busy, setBusy] = useState(false);
  return (
    <button
      type="button"
      disabled={busy}
      className={`${btnCls.ghost} !px-3 !py-1.5`}
      onClick={async () => {
        setBusy(true);
        try {
          const client = createAuthClient({ publishableKey, frontendApi: window.location.origin, syncCookie: true });
          await client.load();
          await client.signOut();
        } finally {
          window.location.assign("/dashboard");
        }
      }}
    >
      {busy ? "Signing out…" : "Sign out"}
    </button>
  );
}
