import { errors } from "../http";
import { resolveSession } from "./sessions";
import type { Instance } from "../db/schema";

/** Frontend API routes that act on the signed-in user. */
export async function requireSession(inst: Instance, refreshToken: string | undefined) {
  const s = refreshToken ? await resolveSession(inst.id, refreshToken) : null;
  if (!s) throw errors.unauthorized();
  return s;
}
