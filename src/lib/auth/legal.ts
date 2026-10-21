import { schema } from "../db";
import { newId } from "../ids";
import type { Instance } from "../db/schema";

type Legal = Instance["legal"];
const DEFAULT: Legal = { required: false, termsUrl: null, privacyUrl: null, version: "1" };

/** Instance terms settings (instances cached before this field existed fall back to defaults). */
export const legalOf = (inst: Instance): Legal => ({ ...DEFAULT, ...(inst.legal ?? {}) });

/** Insert row for an acceptance; call inside the transaction that creates the user. */
export function acceptanceRow(inst: Instance, userId: string, method: "password" | "google" | "github") {
  return { id: newId("la"), instanceId: inst.id, userId, version: legalOf(inst).version, method };
}

export { schema };
