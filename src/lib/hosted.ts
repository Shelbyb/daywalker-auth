import { resolveCname } from "node:dns/promises";
import { and, eq } from "drizzle-orm";
import { z } from "zod";
import { db, schema } from "./db";
import { cache } from "./cache";
import { errors } from "./http";
import { newId, newToken } from "./ids";
import { record } from "./audit";
import { getInstance, invalidateInstance, publishableKey } from "./auth/instance";
import { ownedInstance } from "./dashboard";

export type Branding = NonNullable<schema.Instance["settings"]["branding"]>;
const color = z.string().regex(/^#[0-9a-fA-F]{6}$/, "Use a hex color like #ff6a3d").nullable();
const brandingInput = z.object({
  logoUrl: z.string().url().startsWith("https://", "Logo must be an https URL").max(500).nullable(),
  primaryColor: color,
  backgroundColor: color,
  title: z.string().trim().max(80).nullable(),
});

export async function saveBranding(userId: string, instanceId: string, input: unknown) {
  const inst = await ownedInstance(userId, instanceId);
  const branding = brandingInput.parse(input);
  await db().update(schema.instances).set({ settings: { ...inst.settings, branding }, updatedAt: new Date() }).where(eq(schema.instances.id, instanceId));
  await invalidateInstance(instanceId);
  void record(instanceId, "instance.branding_updated", { actor: { type: "developer", id: userId } });
}

const HOST = /^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const appHostname = () => new URL(process.env.APP_URL ?? "http://localhost").hostname;
/** The hostname customers point their CNAME at. */
export const cnameTarget = () => appHostname();

/** True when `hostname` has a CNAME pointing at this service. */
async function cnamePointsHere(hostname: string) {
  try {
    const target = appHostname().replace(/\.$/, "").toLowerCase();
    return (await resolveCname(hostname)).some((c) => c.replace(/\.$/, "").toLowerCase() === target);
  } catch { return false; }
}

/** Best-effort: attaches the hostname to the DigitalOcean App Platform app so it gets a TLS certificate. Needs DO_API_TOKEN and DO_APP_ID. */
async function attachToHost(hostname: string, remove = false) {
  const token = process.env.DO_API_TOKEN, appId = process.env.DO_APP_ID;
  if (!token || !appId) return;
  try {
    const headers = { Authorization: `Bearer ${token}`, "Content-Type": "application/json" };
    const res = await fetch(`https://api.digitalocean.com/v2/apps/${appId}`, { headers });
    if (!res.ok) return;
    const { app } = (await res.json()) as { app: { spec: { domains?: { domain: string; type?: string }[] } } };
    const spec = app.spec;
    const domains = spec.domains ?? [];
    const has = domains.some((d) => d.domain === hostname);
    if (remove ? !has : has) return;
    spec.domains = remove ? domains.filter((d) => d.domain !== hostname) : [...domains, { domain: hostname, type: "ALIAS" }];
    await fetch(`https://api.digitalocean.com/v2/apps/${appId}`, { method: "PUT", headers, body: JSON.stringify({ spec }) });
  } catch { /* the dashboard still shows the manual steps */ }
}

async function markVerified(d: typeof schema.customDomains.$inferSelect) {
  await db().update(schema.customDomains).set({ verifiedAt: new Date() }).where(eq(schema.customDomains.id, d.id));
  await cache().del(`dom:${d.hostname}`);
  void record(d.instanceId, "instance.domain_verified", { actor: { type: "system", id: "dns" }, data: { hostname: d.hostname } });
}

/** Checks the CNAME of every pending domain on an instance and verifies those that point here. */
export async function autoVerifyPending(instanceId: string) {
  const rows = await db().select().from(schema.customDomains).where(eq(schema.customDomains.instanceId, instanceId));
  for (const d of rows) if (!d.verifiedAt && (await cnamePointsHere(d.hostname))) await markVerified(d);
}

export async function listDomains(userId: string, instanceId: string) {
  await ownedInstance(userId, instanceId);
  return db().select().from(schema.customDomains).where(eq(schema.customDomains.instanceId, instanceId));
}

export async function addDomain(userId: string, instanceId: string, raw: string) {
  await ownedInstance(userId, instanceId);
  const hostname = raw.trim().toLowerCase();
  if (!HOST.test(hostname)) throw errors.badRequest("invalid_hostname", "Enter a valid hostname such as auth.example.com");
  const appHost = new URL(process.env.APP_URL ?? "http://localhost").hostname;
  if (hostname === appHost) throw errors.badRequest("reserved_hostname", "That hostname is reserved");
  const [dup] = await db().select({ id: schema.customDomains.id }).from(schema.customDomains).where(eq(schema.customDomains.hostname, hostname));
  if (dup) throw errors.badRequest("hostname_in_use", "That hostname is already in use");
  await db().insert(schema.customDomains).values({ id: newId("dom"), instanceId, hostname, verifyToken: newToken(16) });
  void attachToHost(hostname);
  void record(instanceId, "instance.domain_added", { actor: { type: "developer", id: userId }, data: { hostname } });
}

/** Checks that the hostname has a CNAME pointing at this service. */
export async function verifyDomain(userId: string, instanceId: string, domainId: string) {
  await ownedInstance(userId, instanceId);
  const [d] = await db().select().from(schema.customDomains).where(and(eq(schema.customDomains.id, domainId), eq(schema.customDomains.instanceId, instanceId)));
  if (!d) throw errors.notFound("Domain not found");
  if (d.verifiedAt) return;
  if (!(await cnamePointsHere(d.hostname))) throw errors.badRequest("cname_not_found", `CNAME not found yet. Point ${d.hostname} at ${appHostname()}; DNS changes can take a while to propagate.`);
  await markVerified(d);
}

export async function removeDomain(userId: string, instanceId: string, domainId: string) {
  await ownedInstance(userId, instanceId);
  const [d] = await db().delete(schema.customDomains).where(and(eq(schema.customDomains.id, domainId), eq(schema.customDomains.instanceId, instanceId))).returning();
  if (d) { await cache().del(`dom:${d.hostname}`); void attachToHost(d.hostname, true); }
}

/** Instance for a verified custom hostname, or null. */
export async function instanceForHost(host: string | null) {
  const h = host?.split(":")[0]?.toLowerCase();
  if (!h) return null;
  const instanceId = await cache().get(`dom:${h}`).then(async (v) => {
    if (v !== null && v !== undefined) return v || null;
    const [row] = await db().select().from(schema.customDomains).where(eq(schema.customDomains.hostname, h));
    let id = row?.verifiedAt ? row.instanceId : "";
    if (row && !row.verifiedAt && (await cnamePointsHere(h))) { await markVerified(row); id = row.instanceId; }
    await cache().set(`dom:${h}`, id, "EX", id ? 300 : 30);
    return id || null;
  });
  if (!instanceId) return null;
  const inst = await getInstance(instanceId);
  return inst ? { inst, pk: publishableKey(inst) } : null;
}

/** Instance for a hosted page: from `pk`, or from the verified custom domain the page is served on. */
export async function hostedInstance(pkParam: string | undefined) {
  const { headers } = await import("next/headers");
  const { parsePublishableKey } = await import("./auth/instance");
  const { env } = await import("./env");
  const h = await headers();
  const host = h.get("x-forwarded-host") ?? h.get("host");
  const custom = await instanceForHost(host);
  const id = parsePublishableKey(pkParam);
  const inst = id ? await getInstance(id) : (custom?.inst ?? null);
  if (!inst) return null;
  const onCustom = custom && custom.inst.id === inst.id;
  const origin = onCustom ? `https://${host!.split(":")[0]}` : env().APP_URL;
  return { inst, pk: publishableKey(inst), origin };
}
