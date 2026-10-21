"use client";

import { createAuthClient, type AuthClient } from "@daywalker/auth";

let client: AuthClient | undefined;

/**
 * The hosted pages use the same SDK customers use. Created lazily in the browser
 * (no `window` during server rendering); no app-domain cookie is needed on this origin.
 */
export function hostedClient(pk: string) {
  return (client ??= createAuthClient({ publishableKey: pk, frontendApi: window.location.origin, syncCookie: false }));
}
