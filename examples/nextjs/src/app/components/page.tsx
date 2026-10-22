"use client";

import { SignedIn, SignedOut, useUser } from "@daywalker/auth/react";

export default function Page() {
  const { user } = useUser();
  return (
    <>
      <SignedIn>
        <p data-testid="signed-in">Signed in as {user?.emailAddresses[0]?.email}</p>
      </SignedIn>
      <SignedOut>
        <p data-testid="signed-out">
          Signed out. <a href="/components/sign-in">Sign in</a> or <a href="/components/sign-up">create an account</a>.
        </p>
      </SignedOut>
    </>
  );
}
