"use client";

import Link from "next/link";
import { SignedIn, SignedOut, SignInButton, UserButton, useUser } from "@daywalker/auth/react";

export function AuthStatus() {
  const { user } = useUser();
  return (
    <>
      <SignedOut>
        <p>You&apos;re signed out.</p>
        <SignInButton /> <SignInButton mode="sign-up">Create account</SignInButton>
      </SignedOut>
      <SignedIn>
        <UserButton afterSignOutUrl="/" />
        <p>Hello, {user?.firstName ?? user?.emailAddresses[0]?.email}.</p>
        {/* Prefetched in production when visible, so navigation is instant */}
        <Link href="/dashboard">Go to dashboard</Link>
      </SignedIn>
    </>
  );
}
