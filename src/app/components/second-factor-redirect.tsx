"use client";

import { useState } from "react";
import { SecondFactorStep } from "./second-factor";

export function SecondFactorRedirect({ pk, redirect }: { pk: string; redirect?: string }) {
  const [done, setDone] = useState(false);
  if (done) return <p className="text-center font-medium">You&apos;re signed in</p>;
  return <SecondFactorStep pk={pk} onDone={() => (redirect ? window.location.assign(redirect) : setDone(true))} />;
}
