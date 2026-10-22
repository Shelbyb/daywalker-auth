"use client";

import { OrganizationSwitcher, SignedIn, SignedOut, UserButton } from "@daywalker/auth/react";

export function Header() {
  return (
    <header style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "12px 24px", borderBottom: "1px solid #e7e5e4" }}>
      <a href="/components" style={{ fontWeight: 600, color: "inherit", textDecoration: "none" }}>Components demo</a>
      <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
        <SignedIn>
          <OrganizationSwitcher />
          <UserButton afterSignOutUrl="/components/sign-in" />
        </SignedIn>
        <SignedOut>
          <a href="/components/sign-in">Sign in</a>
        </SignedOut>
      </div>
    </header>
  );
}
