/**
 * Verified organization domains and enrollment.
 *
 * Proving a domain: (a) a DNS TXT record `daywalker-verify=<token>` at `_daywalker.<domain>`, or (b) a 6-digit code
 * emailed to a role mailbox of the domain (admin@, administrator@, postmaster@, webmaster@, hostmaster@), the same
 * mailboxes certificate authorities accept. Free-mail domains can't be claimed. One organization per instance holds
 * a verified domain (unique index), so a domain can't be hijacked by a second organization.
 *
 * Enrollment (per domain): "none", "suggest" (people with a verified email at the domain see the organization
 * and can join with one click) or "auto_join" (they join when they sign in or verify their email). Only a VERIFIED email
 * address counts, exact domain match (no subdomains), and the joining role can never manage the organization.
 */
import { promises as dns } from "node:dns";
import { readFileSync } from "node:fs";
import { and, eq, isNotNull } from "drizzle-orm";
import { z } from "zod";
import { db, schema } from "../db";
import { cache, rateLimit } from "../cache";
import { decrypt } from "../crypto";
import { errors } from "../http";
import { newId, newToken } from "../ids";
import { sendMail } from "../mail";
import { composeEmail } from "../email-templates";
import { emit } from "../webhooks";
import { record } from "../audit";
import { orgSettings } from "../org-settings";
import { issueCode, consumeCode } from "./codes";
import { assertSafeForAutoJoin } from "./org-roles";
import { requirePermission, assertRoomFor, getOrg, forgetMembership } from "./orgs";
import type { Instance } from "../db/schema";

export const MAX_DOMAINS_PER_ORG = 10;
export const ROLE_MAILBOXES = ["admin", "administrator", "postmaster", "webmaster", "hostmaster"];
export const ENROLLMENT = ["none", "suggest", "auto_join"] as const;
export type Enrollment = (typeof ENROLLMENT)[number];

/** Domains anyone can get an address at: never proof of owning the domain. */
const FREE_MAIL = new Set([
  "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com", "yahoo.com", "ymail.com", "icloud.com", "me.com", "mac.com",
  "aol.com", "proton.me", "protonmail.com", "pm.me", "gmx.com", "gmx.net", "mail.com", "zoho.com", "yandex.com", "yandex.ru", "qq.com", "163.com", "126.com", "fastmail.com", "hey.com", "tutanota.com",
]);

export function normalizeDomain(input: string) {
  const d = input.trim().toLowerCase().replace(/\.$/, "");
  const ok = d.length <= 253 && /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(d);
  if (!ok) throw errors.badRequest("invalid_domain", "Enter a domain like example.com");
  if (FREE_MAIL.has(d)) throw errors.badRequest("domain_not_allowed", "Free email domains can't be claimed");
  return d;
}

const listKey = (instanceId: string) => `orgdom:${instanceId}`;
const forgetList = (instanceId: string) => cache().del(listKey(instanceId));

const view = (d: typeof schema.orgDomains.$inferSelect) => ({
  id: d.id,
  domain: d.domain,
  verified: !!d.verifiedAt,
  verifiedVia: d.verifiedVia,
  enrollment: d.enrollment as Enrollment,
  role: d.role,
  createdAt: d.createdAt,
  ...(d.verifiedAt ? {} : { dns: { type: "TXT", name: `_daywalker.${d.domain}`, value: `daywalker-verify=${d.verificationToken}` } }),
});

async function get(inst: Instance, orgId: string, domainId: string) {
  const [d] = await db().select().from(schema.orgDomains).where(and(eq(schema.orgDomains.id, domainId), eq(schema.orgDomains.orgId, orgId), eq(schema.orgDomains.instanceId, inst.id)));
  if (!d) throw errors.notFound("Domain not found");
  return d;
}

/** Access: a member whose role has org:manage (frontend), or null actor for the backend API. */
async function authorize(inst: Instance, orgId: string, actorId: string | null) {
  if (actorId) await requirePermission(inst.id, orgId, actorId, "org:manage");
  else if (!(await getOrg(inst.id, orgId))) throw errors.notFound("Organization not found");
}

export async function listDomains(inst: Instance, orgId: string, actorId: string | null) {
  await authorize(inst, orgId, actorId);
  const rows = await db().select().from(schema.orgDomains).where(and(eq(schema.orgDomains.orgId, orgId), eq(schema.orgDomains.instanceId, inst.id)));
  return rows.map(view);
}

export async function addDomain(inst: Instance, orgId: string, actorId: string | null, domainInput: string) {
  await authorize(inst, orgId, actorId);
  const domain = normalizeDomain(domainInput);
  const mine = await db().select({ id: schema.orgDomains.id }).from(schema.orgDomains).where(eq(schema.orgDomains.orgId, orgId));
  if (mine.length >= MAX_DOMAINS_PER_ORG) throw errors.limitReached(`An organization can have at most ${MAX_DOMAINS_PER_ORG} domains`);
  const [taken] = await db().select({ id: schema.orgDomains.id }).from(schema.orgDomains).where(and(eq(schema.orgDomains.instanceId, inst.id), eq(schema.orgDomains.domain, domain), isNotNull(schema.orgDomains.verifiedAt)));
  if (taken) throw errors.conflict("domain_taken", "That domain is already verified by an organization");
  const id = newId("dom");
  try {
    await db().insert(schema.orgDomains).values({ id, instanceId: inst.id, orgId, domain, verificationToken: newToken(24) });
  } catch (e) {
    if (((e as { cause?: { code?: string } }).cause?.code ?? (e as { code?: string }).code) === "23505") throw errors.conflict("domain_exists", "This organization already has that domain");
    throw e;
  }
  void record(inst.id, "org_domain.added", { actor: actorId ? { type: "user", id: actorId } : { type: "api" }, target: orgId, data: { domain } });
  return view((await get(inst, orgId, id)));
}

async function txtRecords(name: string): Promise<string[]> {
  // Test switch (same pattern as the other *_TEST_* variables): a JSON file of name -> TXT values. Never on an HTTPS deployment.
  const f = process.env.DNS_TXT_TEST_FILE;
  if (f) {
    if (process.env.APP_URL?.startsWith("https://")) throw new Error("DNS_TXT_TEST_FILE is not allowed on an HTTPS deployment");
    try {
      const map = JSON.parse(readFileSync(f, "utf8")) as Record<string, string[]>;
      return map[name] ?? [];
    } catch {
      return []; // no file yet: nothing published
    }
  }
  try {
    return (await dns.resolveTxt(name)).map((chunks) => chunks.join(""));
  } catch {
    return [];
  }
}

async function markVerified(inst: Instance, d: typeof schema.orgDomains.$inferSelect, via: "dns" | "email", actorId: string | null) {
  try {
    await db().update(schema.orgDomains).set({ verifiedAt: new Date(), verifiedVia: via }).where(eq(schema.orgDomains.id, d.id));
  } catch (e) {
    if (((e as { cause?: { code?: string } }).cause?.code ?? (e as { code?: string }).code) === "23505") throw errors.conflict("domain_taken", "That domain is already verified by another organization");
    throw e;
  }
  await forgetList(inst.id);
  void record(inst.id, "org_domain.verified", { actor: actorId ? { type: "user", id: actorId } : { type: "api" }, target: d.orgId, data: { domain: d.domain, via } });
  return view({ ...d, verifiedAt: new Date(), verifiedVia: via });
}

export async function verifyByDns(inst: Instance, orgId: string, actorId: string | null, domainId: string) {
  await authorize(inst, orgId, actorId);
  const d = await get(inst, orgId, domainId);
  if (d.verifiedAt) return view(d);
  if ((await rateLimit(`${inst.id}:domdns:${d.id}`, 20, 3600)) < 0) throw errors.tooMany();
  const records = await txtRecords(`_daywalker.${d.domain}`);
  if (!records.includes(`daywalker-verify=${d.verificationToken}`))
    throw errors.badRequest("verification_failed", "We couldn't find the TXT record yet. DNS changes can take a while to spread; try again in a few minutes");
  return markVerified(inst, d, "dns", actorId);
}

export const mailboxInput = z.string().trim().toLowerCase().regex(/^[a-z]+$/).refine((m) => ROLE_MAILBOXES.includes(m), `Choose one of: ${ROLE_MAILBOXES.join(", ")}`);

export async function sendDomainEmail(inst: Instance, orgId: string, actorId: string | null, domainId: string, mailbox: string) {
  await authorize(inst, orgId, actorId);
  const d = await get(inst, orgId, domainId);
  if (d.verifiedAt) throw errors.badRequest("already_verified", "This domain is already verified");
  if ((await rateLimit(`${inst.id}:domail:${d.id}`, 5, 3600)) < 0) throw errors.tooMany();
  const code = await issueCode("org_domain", d.id);
  await sendMail({ to: `${mailbox}@${d.domain}`, ...(await composeEmail(inst, "verify_email", { code, expires_minutes: "10" })) });
  return { sentTo: `${mailbox}@${d.domain}` };
}

export async function verifyByEmail(inst: Instance, orgId: string, actorId: string | null, domainId: string, code: string) {
  await authorize(inst, orgId, actorId);
  const d = await get(inst, orgId, domainId);
  if (d.verifiedAt) return view(d);
  if (!(await consumeCode("org_domain", d.id, code))) throw errors.badRequest("invalid_code", "That code is incorrect or has expired");
  return markVerified(inst, d, "email", actorId);
}

export async function updateDomain(inst: Instance, orgId: string, actorId: string | null, domainId: string, input: { enrollment?: Enrollment; role?: string | null }) {
  await authorize(inst, orgId, actorId);
  const d = await get(inst, orgId, domainId);
  const enrollment = input.enrollment ?? (d.enrollment as Enrollment);
  const role = input.role === undefined ? d.role : input.role;
  if (enrollment !== "none" && !d.verifiedAt) throw errors.badRequest("domain_unverified", "Verify the domain before turning on enrollment");
  await assertSafeForAutoJoin(inst.id, role ?? orgSettings(inst).defaultRole);
  await db().update(schema.orgDomains).set({ enrollment, role }).where(eq(schema.orgDomains.id, d.id));
  await forgetList(inst.id);
  void record(inst.id, "org_domain.updated", { actor: actorId ? { type: "user", id: actorId } : { type: "api" }, target: orgId, data: { domain: d.domain, enrollment, role } });
  return view({ ...d, enrollment, role });
}

/** Removing a domain stops future enrollment; people who already joined stay members. */
export async function removeDomain(inst: Instance, orgId: string, actorId: string | null, domainId: string) {
  await authorize(inst, orgId, actorId);
  const d = await get(inst, orgId, domainId);
  await db().delete(schema.orgDomains).where(eq(schema.orgDomains.id, d.id));
  await forgetList(inst.id);
  void record(inst.id, "org_domain.removed", { actor: actorId ? { type: "user", id: actorId } : { type: "api" }, target: orgId, data: { domain: d.domain } });
}

// ---------- Enrollment ----------

type Enrollable = { orgId: string; domain: string; enrollment: Enrollment; role: string | null };

async function enrollable(instanceId: string): Promise<Enrollable[]> {
  const hit = await cache().get(listKey(instanceId));
  if (hit) return JSON.parse(hit);
  const rows = await db()
    .select({ orgId: schema.orgDomains.orgId, domain: schema.orgDomains.domain, enrollment: schema.orgDomains.enrollment, role: schema.orgDomains.role })
    .from(schema.orgDomains)
    .where(and(eq(schema.orgDomains.instanceId, instanceId), isNotNull(schema.orgDomains.verifiedAt)));
  const list = rows.filter((r) => r.enrollment !== "none") as Enrollable[];
  await cache().set(listKey(instanceId), JSON.stringify(list), "EX", 60);
  return list;
}

/** Domains of the person's VERIFIED email addresses. */
async function verifiedDomains(instanceId: string, userId: string) {
  const rows = await db()
    .select({ id: schema.emailAddresses.id, enc: schema.emailAddresses.emailEnc, verifiedAt: schema.emailAddresses.verifiedAt })
    .from(schema.emailAddresses)
    .where(and(eq(schema.emailAddresses.userId, userId), eq(schema.emailAddresses.instanceId, instanceId)));
  return new Set(rows.filter((r) => r.verifiedAt).map((r) => decrypt(r.enc, `email_addresses.email:${r.id}`).split("@").pop()!.toLowerCase()));
}

async function join(inst: Instance, e: Enrollable, userId: string, how: "auto" | "suggestion") {
  const [org] = await db().select({ id: schema.organizations.id }).from(schema.organizations).where(and(eq(schema.organizations.id, e.orgId), eq(schema.organizations.instanceId, inst.id)));
  if (!org) return false;
  const role = e.role ?? orgSettings(inst).defaultRole;
  await assertRoomFor(inst, e.orgId);
  const ins = await db().insert(schema.memberships).values({ orgId: e.orgId, userId, role }).onConflictDoNothing().returning({ u: schema.memberships.userId });
  if (!ins.length) return false;
  await forgetMembership(e.orgId, userId);
  void emit(inst.id, "organizationMembership.created", { organizationId: e.orgId, userId, role, via: "domain" });
  void record(inst.id, "org_domain.joined", { actor: { type: "user", id: userId }, target: e.orgId, data: { domain: e.domain, role, how } });
  return true;
}

/** Joins the person to every organization with auto_join for a verified email domain of theirs. Never throws. */
export async function autoJoinByDomain(inst: Instance, userId: string) {
  try {
    if (!orgSettings(inst).enabled) return;
    const list = (await enrollable(inst.id)).filter((e) => e.enrollment === "auto_join");
    if (!list.length) return;
    const mine = await verifiedDomains(inst.id, userId);
    for (const e of list) if (mine.has(e.domain)) await join(inst, e, userId, "auto").catch(() => false);
  } catch (err) {
    console.error("[org-domains] auto-join failed", (err as Error).message);
  }
}

/** Organizations the person could join through a verified domain (enrollment "suggest"), minus the ones they're in. */
export async function suggestionsFor(inst: Instance, userId: string) {
  if (!orgSettings(inst).enabled) return [];
  const list = (await enrollable(inst.id)).filter((e) => e.enrollment === "suggest");
  if (!list.length) return [];
  const mine = await verifiedDomains(inst.id, userId);
  const hits = list.filter((e) => mine.has(e.domain));
  if (!hits.length) return [];
  const member = await db().select({ orgId: schema.memberships.orgId }).from(schema.memberships).where(eq(schema.memberships.userId, userId));
  const out: { id: string; name: string; slug: string; domain: string }[] = [];
  for (const e of hits) {
    if (member.some((m) => m.orgId === e.orgId)) continue;
    const org = await getOrg(inst.id, e.orgId);
    if (org) out.push({ id: org.id, name: org.name, slug: org.slug, domain: e.domain });
  }
  return out;
}

export async function acceptSuggestion(inst: Instance, userId: string, orgId: string) {
  if (!orgSettings(inst).enabled) throw errors.forbidden("Organizations are turned off for this application");
  const e = (await enrollable(inst.id)).find((x) => x.orgId === orgId && x.enrollment === "suggest");
  const mine = e ? await verifiedDomains(inst.id, userId) : new Set<string>();
  // Same answer for "no such suggestion" and "not for you": nothing to probe.
  if (!e || !mine.has(e.domain)) throw errors.notFound("No such suggestion");
  await join(inst, e, userId, "suggestion");
  const org = (await getOrg(inst.id, orgId))!;
  return { id: org.id, name: org.name, slug: org.slug, role: e.role ?? orgSettings(inst).defaultRole };
}

export const verifyBody = z.union([
  z.object({ method: z.literal("dns") }),
  z.object({ method: z.literal("email"), mailbox: mailboxInput }),
  z.object({ method: z.literal("email"), code: z.string().trim().max(10) }),
]);

export async function runVerify(inst: Instance, orgId: string, actorId: string | null, domainId: string, b: z.infer<typeof verifyBody>) {
  if (b.method === "dns") return verifyByDns(inst, orgId, actorId, domainId);
  if ("mailbox" in b) return sendDomainEmail(inst, orgId, actorId, domainId, b.mailbox);
  return verifyByEmail(inst, orgId, actorId, domainId, b.code);
}
