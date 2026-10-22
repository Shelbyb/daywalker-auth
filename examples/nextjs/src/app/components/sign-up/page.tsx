"use client";

import { SignUp } from "@daywalker/auth/react";

export default function Page() {
  return <SignUp redirectUrl="/components" signInUrl="/components/sign-in" />;
}
