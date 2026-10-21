import { errors } from "../http";
import { resolveSession } from "./sessions";
import type { Instance } from "../db/schema";

/** Frontend API routes that act on the signed-in user. */
export async function requireSession(inst: Instance, refreshToken: string | undefined) {
  const s = refreshToken ? await resolveSession(inst.id, refreshToken) : null;
  if (!s) throw errors.unauthorized();
  return s;
}

const FRESH_MS = 15 * 60_000;

/**
 * For actions that add a lasting way into the account (e.g. registering a passkey): the
 * session must have started recently, so an old or hijacked session can't quietly add one.
 */
export async function requireFreshSession(inst: Instance, refreshToken: string | undefined) {
  const s = await requireSession(inst, refreshToken);
  if (!s.createdAt || Date.now() - new Date(s.createdAt).getTime() > FRESH_MS)
    throw errors.forbidden("For your security, please sign in again to continue").withCode("reauth_required");
  return s;
}
