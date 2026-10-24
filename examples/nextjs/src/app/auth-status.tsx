"use client";

import Link from "next/link";
import { AccountPortalProfile, AccountPortalSignIn, AccountPortalSignUp, SignedIn, SignedOut, UserButton, useUser } from "@daywalker/auth/react";

export function AuthStatus() {
  const { user } = useUser();
  return (
    <>
      <SignedOut>
        <p>You&apos;re signed out.</p>
        {/* Links to the hosted Account Portal; you come back to this page afterwards */}
        <AccountPortalSignIn /> <AccountPortalSignUp>Create account</AccountPortalSignUp>
      </SignedOut>
      <SignedIn>
        <UserButton afterSignOutUrl="/" />
        <p>Hello, {user?.firstName ?? user?.emailAddresses[0]?.email}.</p>
        {/* Prefetched in production when visible, so navigation is instant */}
        <Link href="/dashboard">Go to dashboard</Link> <AccountPortalProfile>Manage account</AccountPortalProfile>
      </SignedIn>
    </>
  );
}
