import type { Instance } from "./db/schema";

export type OrgSettings = {
  enabled: boolean;
  /** Max members per organization; null = unlimited. */
  membershipLimit: number | null;
  allowUserCreation: boolean;
  /** Max organizations one user may create; null = unlimited. */
  creationLimit: number | null;
  /** "admin", "member" or a custom role key. */
  creatorRole: string;
  defaultRole: string;
  allowAdminDelete: boolean;
  allowPersonalAccounts: boolean;
};

export const ORG_SETTINGS_DEFAULTS: OrgSettings = {
  enabled: true,
  membershipLimit: null,
  allowUserCreation: true,
  creationLimit: null,
  creatorRole: "admin",
  defaultRole: "member",
  allowAdminDelete: true,
  allowPersonalAccounts: true,
};

const limit = (v: unknown) => (typeof v === "number" && Number.isInteger(v) && v > 0 ? v : null);
const role = (v: unknown, d: string) => (typeof v === "string" && /^[a-z][a-z0-9_]{1,30}$/.test(v) ? v : d);
const bool = (v: unknown, d: boolean) => (typeof v === "boolean" ? v : d);

/** The instance's organization settings with defaults filled in (defaults keep the original behaviour). */
export function orgSettings(inst: Pick<Instance, "settings">): OrgSettings {
  const o = inst.settings?.organizations ?? {};
  const d = ORG_SETTINGS_DEFAULTS;
  return {
    enabled: bool(o.enabled, d.enabled),
    membershipLimit: limit(o.membershipLimit),
    allowUserCreation: bool(o.allowUserCreation, d.allowUserCreation),
    creationLimit: limit(o.creationLimit),
    creatorRole: role(o.creatorRole, d.creatorRole),
    defaultRole: role(o.defaultRole, d.defaultRole),
    allowAdminDelete: bool(o.allowAdminDelete, d.allowAdminDelete),
    allowPersonalAccounts: bool(o.allowPersonalAccounts, d.allowPersonalAccounts),
  };
}
