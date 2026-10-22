/**
 * Enterprise SSO over SAML 2.0 (SP-initiated only).
 *
 * The XML signature work is done by @node-saml/node-saml (xml-crypto underneath). On top of it:
 * - Every sign-in starts here: we create the AuthnRequest, and the response must answer that exact
 *   request (InResponseTo), so IdP-initiated and replayed responses are refused.
 * - The state (RelayState) is single-use and bound to the browser with a cookie, like OAuth.
 * - Assertions must be signed by one of the connection's certificates, for our audience and ACS
 *   URL, within the allowed time window.
 * - The email is only trusted if its domain is one of the connection's domains, so an identity
 *   provider can't vouch for addresses it doesn't own.
 */
import { X509Certificate } from "node:crypto";
import { and, eq } from "drizzle-orm";
import { DOMParser } from "@xmldom/xmldom";
import { SAML, ValidateInResponseTo, type CacheProvider, type Profile } from "@node-saml/node-saml";
import { z } from "zod";
import { db, schema } from "../db";
import { cache } from "../cache";
import { decrypt, encrypt } from "../crypto";
import { env } from "../env";
import { errors } from "../http";
import { newId, newToken, sha256 } from "../ids";
import { record } from "../audit";
import type { Instance } from "../db/schema";
import { linkOrCreate } from "./oauth";

export const STATE_COOKIE = "__dw_saml";
const STATE_TTL = 600;

export const spEntityId = (connectionId: string) => `${env().APP_URL}/v1/saml/${connectionId}/metadata`;
export const acsUrl = (connectionId: string) => `${env().APP_URL}/v1/saml/${connectionId}/acs`;

type Connection = typeof schema.samlConnections.$inferSelect;

// ---------- Configuration ----------

const domainRe = /^(?=.{3,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const urlOk = (u: string) => u.startsWith("https://") || process.env.ALLOW_INSECURE_TRANSPORT === "1";

/** Normalizes a PEM or bare base64 certificate, and refuses anything that isn't a valid, current X.509 certificate. */
export function normalizeCert(raw: string) {
  const b64 = raw.replace(/-----(BEGIN|END) CERTIFICATE-----/g, "").replace(/\s+/g, "");
  if (!/^[A-Za-z0-9+/=]{100,20000}$/.test(b64)) throw errors.badRequest("invalid_certificate", "That isn't a valid X.509 certificate");
  let cert: X509Certificate;
  try {
    cert = new X509Certificate(`-----BEGIN CERTIFICATE-----\n${b64.match(/.{1,64}/g)!.join("\n")}\n-----END CERTIFICATE-----\n`);
  } catch {
    throw errors.badRequest("invalid_certificate", "That isn't a valid X.509 certificate");
  }
  if (new Date(cert.validTo) < new Date()) throw errors.badRequest("invalid_certificate", "That certificate has expired");
  return b64;
}

export const connectionInput = z.object({
  name: z.string().trim().min(1).max(100),
  organizationId: z.string().max(100).nullish(),
  idpEntityId: z.string().trim().min(1).max(1000),
  ssoUrl: z.string().trim().url().max(2000).refine(urlOk, "The sign-in URL must use https"),
  certificates: z.array(z.string().max(20000)).min(1).max(3),
  domains: z.array(z.string().trim().toLowerCase().regex(domainRe, "Enter domains like example.com")).min(1).max(20),
  enabled: z.boolean().default(true),
});

/** Reads entity ID, HTTP-Redirect SSO URL and signing certificates from IdP metadata XML. */
export function parseIdpMetadata(xml: string) {
  if (xml.length > 200_000) throw errors.badRequest("invalid_metadata", "That metadata is too large");
  if (/<!DOCTYPE|<!ENTITY/i.test(xml)) throw errors.badRequest("invalid_metadata", "Metadata with a DOCTYPE isn't accepted");
  const doc = new DOMParser().parseFromString(xml, "text/xml");
  const all = (name: string) => Array.from(doc.getElementsByTagNameNS("*", name));
  const entity = all("EntityDescriptor")[0];
  const idp = all("IDPSSODescriptor")[0];
  if (!entity || !idp) throw errors.badRequest("invalid_metadata", "That doesn't look like identity provider metadata");
  const sso = Array.from(idp.getElementsByTagNameNS("*", "SingleSignOnService")).find((e) => e.getAttribute("Binding")?.endsWith("HTTP-Redirect"));
  const certs = Array.from(idp.getElementsByTagNameNS("*", "KeyDescriptor"))
    .filter((k) => !k.getAttribute("use") || k.getAttribute("use") === "signing")
    .flatMap((k) => Array.from(k.getElementsByTagNameNS("*", "X509Certificate")).map((c) => c.textContent ?? ""));
  if (!sso?.getAttribute("Location")) throw errors.badRequest("invalid_metadata", "The metadata has no HTTP-Redirect sign-in URL");
  if (!certs.length) throw errors.badRequest("invalid_metadata", "The metadata has no signing certificate");
  return { idpEntityId: entity.getAttribute("entityID") ?? "", ssoUrl: sso.getAttribute("Location")!, certificates: [...new Set(certs)].slice(0, 3) };
}

function view(c: Connection, domains: string[]) {
  return {
    id: c.id,
    name: c.name,
    organizationId: c.orgId,
    idpEntityId: c.idpEntityId,
    ssoUrl: c.ssoUrl,
    certificates: c.certificates.map((b64) => {
      const x = new X509Certificate(Buffer.from(b64, "base64"));
      return { subject: x.subject, validTo: x.validTo, fingerprint256: x.fingerprint256 };
    }),
    domains,
    enabled: c.enabled,
    spEntityId: spEntityId(c.id),
    acsUrl: acsUrl(c.id),
    createdAt: c.createdAt,
  };
}

async function domainsOf(connectionId: string) {
  return (await db().select({ d: schema.samlDomains.domain }).from(schema.samlDomains).where(eq(schema.samlDomains.connectionId, connectionId))).map((r) => r.d);
}

async function load(instanceId: string, id: string) {
  const [c] = await db().select().from(schema.samlConnections).where(and(eq(schema.samlConnections.id, id), eq(schema.samlConnections.instanceId, instanceId)));
  if (!c) throw errors.notFound("SSO connection not found");
  return c;
}

async function checkOrg(instanceId: string, orgId: string | null | undefined) {
  if (!orgId) return null;
  const [o] = await db().select({ id: schema.organizations.id }).from(schema.organizations).where(and(eq(schema.organizations.id, orgId), eq(schema.organizations.instanceId, instanceId)));
  if (!o) throw errors.badRequest("invalid_organization", "That organization doesn't exist in this instance");
  return o.id;
}

/** Accepts either explicit fields or `metadataXml` (which fills in entity ID, SSO URL and certificates). */
export function resolveInput(raw: Record<string, unknown>) {
  const fromMeta = typeof raw.metadataXml === "string" && raw.metadataXml.trim() ? parseIdpMetadata(raw.metadataXml) : {};
  const input = connectionInput.parse({ ...raw, ...fromMeta });
  return { ...input, certificates: input.certificates.map(normalizeCert), domains: [...new Set(input.domains)] };
}

async function writeDomains(tx: Parameters<Parameters<ReturnType<typeof db>["transaction"]>[0]>[0], instanceId: string, connectionId: string, domains: string[]) {
  await tx.delete(schema.samlDomains).where(eq(schema.samlDomains.connectionId, connectionId));
  try {
    await tx.insert(schema.samlDomains).values(domains.map((domain) => ({ instanceId, domain, connectionId })));
  } catch (e) {
    const code = (e as { cause?: { code?: string } }).cause?.code ?? (e as { code?: string }).code;
    if (code === "23505") throw errors.conflict("domain_taken", "One of those domains already belongs to another SSO connection");
    throw e;
  }
}

export async function createConnection(instanceId: string, raw: Record<string, unknown>) {
  const input = resolveInput(raw);
  const orgId = await checkOrg(instanceId, input.organizationId);
  const id = newId("saml");
  await db().transaction(async (tx) => {
    await tx.insert(schema.samlConnections).values({ id, instanceId, name: input.name, orgId, idpEntityId: input.idpEntityId, ssoUrl: input.ssoUrl, certificates: input.certificates, enabled: input.enabled });
    await writeDomains(tx, instanceId, id, input.domains);
  });
  return getConnection(instanceId, id);
}

export async function updateConnection(instanceId: string, id: string, raw: Record<string, unknown>) {
  const c = await load(instanceId, id);
  const merged = { name: c.name, organizationId: c.orgId, idpEntityId: c.idpEntityId, ssoUrl: c.ssoUrl, certificates: c.certificates, domains: await domainsOf(id), enabled: c.enabled, ...raw };
  const input = resolveInput(merged);
  const orgId = await checkOrg(instanceId, input.organizationId);
  await db().transaction(async (tx) => {
    await tx.update(schema.samlConnections).set({ name: input.name, orgId, idpEntityId: input.idpEntityId, ssoUrl: input.ssoUrl, certificates: input.certificates, enabled: input.enabled, updatedAt: new Date() }).where(eq(schema.samlConnections.id, id));
    await writeDomains(tx, instanceId, id, input.domains);
  });
  return getConnection(instanceId, id);
}

export async function getConnection(instanceId: string, id: string) {
  return view(await load(instanceId, id), await domainsOf(id));
}

export async function listConnections(instanceId: string) {
  const rows = await db().select().from(schema.samlConnections).where(eq(schema.samlConnections.instanceId, instanceId));
  return Promise.all(rows.map(async (c) => view(c, await domainsOf(c.id))));
}

export async function deleteConnection(instanceId: string, id: string) {
  await load(instanceId, id);
  await db().delete(schema.samlConnections).where(eq(schema.samlConnections.id, id));
}

export async function hasSso(instanceId: string) {
  const [r] = await db().select({ id: schema.samlConnections.id }).from(schema.samlConnections).where(and(eq(schema.samlConnections.instanceId, instanceId), eq(schema.samlConnections.enabled, true))).limit(1);
  return !!r;
}

/** Which enabled connection handles this email's domain, if any. */
export async function connectionForEmail(instanceId: string, email: string) {
  const domain = email.trim().toLowerCase().split("@")[1] ?? "";
  if (!domain) return null;
  const [r] = await db()
    .select({ c: schema.samlConnections })
    .from(schema.samlDomains)
    .innerJoin(schema.samlConnections, eq(schema.samlConnections.id, schema.samlDomains.connectionId))
    .where(and(eq(schema.samlDomains.instanceId, instanceId), eq(schema.samlDomains.domain, domain), eq(schema.samlConnections.enabled, true)));
  return r?.c ?? null;
}

// ---------- Protocol ----------

/** node-saml's request-ID cache, backed by Valkey. Only the one request ID we expect is accepted. */
function requestCache(expectedId?: string): CacheProvider {
  const key = (id: string) => `saml:req:${sha256(id)}`;
  return {
    async saveAsync(id, value) {
      await cache().set(key(id), value, "EX", STATE_TTL);
      return { value, createdAt: Date.now() };
    },
    async getAsync(id) {
      if (expectedId !== undefined && id !== expectedId) return null; // answers a different request
      return cache().get(key(id));
    },
    async removeAsync(id) {
      if (!id) return null;
      const v = await cache().getdel(key(id));
      return v;
    },
  };
}

function samlFor(c: Connection, opts: { requestId?: string; expectedId?: string } = {}) {
  return new SAML({
    entryPoint: c.ssoUrl,
    issuer: spEntityId(c.id),
    callbackUrl: acsUrl(c.id),
    audience: spEntityId(c.id),
    idpIssuer: c.idpEntityId,
    idpCert: c.certificates,
    wantAssertionsSigned: true,
    wantAuthnResponseSigned: false,
    signatureAlgorithm: "sha256",
    digestAlgorithm: "sha256",
    validateInResponseTo: ValidateInResponseTo.always,
    requestIdExpirationPeriodMs: STATE_TTL * 1000,
    acceptedClockSkewMs: 60_000,
    maxAssertionAgeMs: 10 * 60_000,
    identifierFormat: null,
    disableRequestedAuthnContext: true,
    cacheProvider: requestCache(opts.expectedId),
    ...(opts.requestId ? { generateUniqueId: () => opts.requestId! } : {}),
  });
}

export function spMetadata(c: Connection) {
  return samlFor(c).generateServiceProviderMetadata(null, null);
}

export async function connectionById(id: string) {
  const [c] = await db().select().from(schema.samlConnections).where(eq(schema.samlConnections.id, id));
  return c ?? null;
}

type Pending = { instanceId: string; connectionId: string; requestId: string; redirect: string | null; legalAccepted: boolean };

/** Step 1: returns the IdP URL and a state value that must also be set as an HttpOnly cookie. */
export async function startSso(inst: Instance, email: string, redirect: string | null, legalAccepted: boolean) {
  const c = await connectionForEmail(inst.id, email);
  if (!c) throw errors.badRequest("sso_not_configured", "Single sign-on isn't set up for that email domain");
  const state = newToken(32);
  const requestId = `_${newToken(20)}`;
  const pending: Pending = { instanceId: inst.id, connectionId: c.id, requestId, redirect, legalAccepted };
  await cache().set(`saml:state:${sha256(state)}`, encrypt(JSON.stringify(pending), "saml_state"), "EX", STATE_TTL);
  const url = await samlFor(c, { requestId }).getAuthorizeUrlAsync(state, undefined, {});
  return { url, state, maxAge: STATE_TTL, connection: c };
}

/** Single use, and only from the browser that started it. */
export async function takeState(connectionId: string, state: string | null, cookieState: string | undefined) {
  if (!state || !cookieState || state.length > 200 || state !== cookieState) return null;
  const raw = await cache().getdel(`saml:state:${sha256(state)}`);
  if (!raw) return null;
  const p = JSON.parse(decrypt(raw, "saml_state")) as Pending;
  return p.connectionId === connectionId ? p : null;
}

const EMAIL_ATTRS = ["email", "mail", "emailAddress", "urn:oid:0.9.2342.19200300.100.1.3", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"];
const FIRST_ATTRS = ["firstName", "givenName", "given_name", "urn:oid:2.5.4.42", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"];
const LAST_ATTRS = ["lastName", "surname", "sn", "family_name", "urn:oid:2.5.4.4", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"];
const attr = (p: Profile, names: string[]) => {
  for (const n of names) {
    const v = p[n];
    const s = Array.isArray(v) ? v[0] : v;
    if (typeof s === "string" && s.trim()) return s.trim().slice(0, 254);
  }
  return null;
};

/** Step 2: validate the IdP's response and sign the user in. Returns the user ID. */
export async function completeSso(inst: Instance, connectionId: string, pending: Pending, samlResponse: string) {
  const c = await connectionById(connectionId);
  if (!c || !c.enabled || c.instanceId !== inst.id) throw errors.badRequest("sso_not_configured", "This SSO connection is no longer available");
  let profile: Profile | null;
  try {
    ({ profile } = await samlFor(c, { expectedId: pending.requestId }).validatePostResponseAsync({ SAMLResponse: samlResponse }));
  } catch (e) {
    void record(inst.id, "user.sign_in_failed", { target: null, data: { reason: "saml_invalid", connectionId, detail: String((e as Error).message).slice(0, 120) } });
    throw errors.badRequest("oauth_failed", "The identity provider's response couldn't be verified");
  }
  if (!profile?.nameID) throw errors.badRequest("oauth_failed", "The identity provider didn't say who signed in");
  // The library checks the signature; the assertion must also name the configured identity provider.
  if (profile.issuer !== c.idpEntityId) {
    void record(inst.id, "user.sign_in_failed", { target: null, data: { reason: "saml_invalid", connectionId, detail: "issuer mismatch" } });
    throw errors.badRequest("oauth_failed", "The identity provider's response couldn't be verified");
  }
  const email = (attr(profile, EMAIL_ATTRS) ?? (/^[^@\s]+@[^@\s]+$/.test(profile.nameID) ? profile.nameID : null))?.toLowerCase() ?? null;
  const domain = email?.split("@")[1];
  const ownsDomain = !!domain && (await domainsOf(c.id)).includes(domain);
  const userId = await linkOrCreate(
    inst,
    "saml",
    { id: `${c.id}:${profile.nameID}`, email, emailVerified: ownsDomain, firstName: attr(profile, FIRST_ATTRS), lastName: attr(profile, LAST_ATTRS), imageUrl: null },
    pending.legalAccepted,
  );
  if (c.orgId) {
    // Just-in-time membership in the connection's organization.
    await db().insert(schema.memberships).values({ orgId: c.orgId, userId, role: "member" }).onConflictDoNothing();
  }
  return userId;
}
