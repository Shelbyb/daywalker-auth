"use client";

import { SignIn } from "@daywalker/auth/react";

export default function Page() {
  return <SignIn redirectUrl="/components" signUpUrl="/components/sign-up" />;
}
