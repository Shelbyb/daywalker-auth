"use client";

import { useState } from "react";
import { useAuth } from "@daywalker/auth/react";

/** Calls your own API with `Authorization: Bearer <jwt>` attached by the SDK. */
export function CallApi() {
  const { authFetch } = useAuth();
  const [result, setResult] = useState<string>();
  return (
    <div>
      <button onClick={async () => setResult(JSON.stringify(await (await authFetch("/api/me")).json(), null, 2))}>Call /api/me</button>
      {result && <pre>{result}</pre>}
    </div>
  );
}
