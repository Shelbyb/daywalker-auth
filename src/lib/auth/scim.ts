/**
 * SCIM 2.0 user provisioning (RFC 7643 / 7644), one endpoint per SSO connection.
 *
 * The identity provider (Okta, Entra ID, ...) calls these endpoints with a bearer token to create,
 * update and deactivate people automatically. Rules that keep it safe:
 * - The token is random, shown once, and only its SHA-256 is stored. Rotating it revokes the old one.
 * - A connection can only manage users it created or adopted, and only at the email domains it owns.
 * - Deactivating (`active: false`) suspends the account and signs it out everywhere.
 * - Adopting an existing account whose email was never verified removes its password and sessions first,
 *   the same as SAML does, so a pre-registered account can't be taken over.
 */
import { and, asc, eq, sql } from "drizzle-orm";
import { z } from "zod";
import { db, schema } from "../db";
import { cache, rateLimit } from "../cache";
import { blindIndex, encrypt, encryptNullable } from "../crypto";
import { env } from "../env";
import { errors } from "../http";
import { newId, newToken, sha256 } from "../ids";
import { record } from "../audit";
import { emit } from "../webhooks";
import { getInstance } from "./instance";
import { domainsOf } from "./saml";
import { deleteUser, getUser, setBanned } from "./users";
import type { Instance } from "../db/schema";

export const SCHEMAS = {
  user: "urn:ietf:params:scim:schemas:core:2.0:User",
  list: "urn:ietf:params:scim:api:messages:2.0:ListResponse",
  error: "urn:ietf:params:scim:api:messages:2.0:Error",
  patch: "urn:ietf:params:scim:api:messages:2.0:PatchOp",
};
const MAX_PAGE = 200;

/** A SCIM-shaped error: `scimType` is one of the RFC's names (uniqueness, invalidValue, ...). */
export class ScimError extends Error {
  constructor(public status: number, public scimType: string | undefined, detail: string) {
    super(detail);
  }
}

export const scimBaseUrl = (connectionId: string) => `${env().APP_URL}/v1/scim/v2/${connectionId}`;

// ---------- Token ----------

type Connection = typeof schema.samlConnections.$inferSelect;
async function connection(instanceId: string, id: string) {
  const [c] = await db().select().from(schema.samlConnections).where(and(eq(schema.samlConnections.id, id), eq(schema.samlConnections.instanceId, instanceId)));
  if (!c) throw errors.notFound("SSO connection not found");
  return c;
}

/** Makes (or replaces) the connection's token. The plaintext is returned once and never stored. */
export async function createScimToken(instanceId: string, connectionId: string) {
  await connection(instanceId, connectionId);
  const token = `scim_${newToken(32)}`;
  await db()
    .update(schema.samlConnections)
    .set({ scimTokenHash: sha256(token), scimTokenPrefix: token.slice(0, 10), scimTokenCreatedAt: new Date() })
    .where(eq(schema.samlConnections.id, connectionId));
  return { token, baseUrl: scimBaseUrl(connectionId) };
}

/** Turns provisioning off. The identity provider's calls start failing immediately. */
export async function revokeScimToken(instanceId: string, connectionId: string) {
  await connection(instanceId, connectionId);
  await db()
    .update(schema.samlConnections)
    .set({ scimTokenHash: null, scimTokenPrefix: null, scimTokenCreatedAt: null })
    .where(eq(schema.samlConnections.id, connectionId));
}

export type ScimCtx = { inst: Instance; conn: Connection; domains: string[] };

/** Checks the bearer token for this connection. Every failure is the same 401. */
export async function authenticateScim(req: Request, connectionId: string): Promise<ScimCtx> {
  const token = req.headers.get("authorization")?.match(/^Bearer (scim_[A-Za-z0-9_-]{20,100})$/)?.[1];
  const fail = () => new ScimError(401, undefined, "Invalid or missing bearer token");
  if (!token) throw fail();
  const [conn] = await db().select().from(schema.samlConnections).where(and(eq(schema.samlConnections.id, connectionId), eq(schema.samlConnections.scimTokenHash, sha256(token))));
  if (!conn) throw fail();
  if ((await rateLimit(`scim:${conn.id}`, 600, 60)) < 0) throw new ScimError(429, undefined, "Too many requests");
  const inst = await getInstance(conn.instanceId);
  if (!inst) throw fail();
  return { inst, conn, domains: await domainsOf(conn.id) };
}

// ---------- Mapping ----------

const emailIndex = (instanceId: string, email: string) => blindIndex(email, `email:${instanceId}`);

async function externalIdOf(connId: string, userId: string) {
  const [l] = await db().select({ e: schema.scimUsers.externalId }).from(schema.scimUsers).where(and(eq(schema.scimUsers.connectionId, connId), eq(schema.scimUsers.userId, userId)));
  return l ? (l.e ?? null) : undefined; // undefined: not managed by this connection
}

async function toScim(c: ScimCtx, userId: string) {
  const user = await getUser(c.inst.id, userId, { includePrivate: true });
  const ext = await externalIdOf(c.conn.id, userId);
  if (!user || ext === undefined) throw new ScimError(404, undefined, "User not found");
  const primary = user.emailAddresses.find((e) => e.primary) ?? user.emailAddresses[0];
  const formatted = [user.firstName, user.lastName].filter(Boolean).join(" ");
  return {
    schemas: [SCHEMAS.user],
    id: user.id,
    ...(ext ? { externalId: ext } : {}),
    userName: primary?.email ?? "",
    name: { givenName: user.firstName ?? "", familyName: user.lastName ?? "", formatted },
    displayName: formatted || primary?.email || "",
    emails: primary ? [{ value: primary.email, type: "work", primary: true }] : [],
    active: !user.banned,
    meta: { resourceType: "User", created: user.createdAt, location: `${scimBaseUrl(c.conn.id)}/Users/${user.id}` },
  };
}

// ---------- Input ----------

const str = (max: number) => z.string().trim().max(max);
const emailSchema = z.string().trim().toLowerCase().email().max(254);
const asBool = (v: unknown) => (typeof v === "boolean" ? v : typeof v === "string" && /^(true|false)$/i.test(v) ? v.toLowerCase() === "true" : undefined);

type Changes = { userName?: string; givenName?: string; familyName?: string; active?: boolean; externalId?: string | null };

/** Pulls the fields we manage out of a SCIM User body (create and replace). */
function fromBody(body: unknown): Changes {
  const b = z
    .object({
      userName: str(254).optional(),
      externalId: str(255).nullish(),
      name: z.object({ givenName: str(254).optional(), familyName: str(254).optional() }).partial().optional(),
      emails: z.array(z.object({ value: str(254), primary: z.unknown().optional() }).passthrough()).max(20).optional(),
      active: z.unknown().optional(),
    })
    .passthrough()
    .safeParse(body);
  if (!b.success) throw new ScimError(400, "invalidSyntax", "The request body isn't a valid SCIM User");
  const d = b.data;
  const primaryEmail = d.emails?.find((e) => asBool(e.primary) === true)?.value ?? d.emails?.[0]?.value;
  const c: Changes = {};
  const userName = d.userName || primaryEmail;
  if (userName) c.userName = userName;
  if (d.name?.givenName !== undefined) c.givenName = d.name.givenName;
  if (d.name?.familyName !== undefined) c.familyName = d.name.familyName;
  if (d.externalId !== undefined) c.externalId = d.externalId ?? null;
  if (d.active !== undefined) {
    const a = asBool(d.active);
    if (a === undefined) throw new ScimError(400, "invalidValue", "`active` must be true or false");
    c.active = a;
  }
  return c;
}

/** Reads a PatchOp body. Handles Okta's path-less form and Entra ID's string booleans and email filters. */
function fromPatch(body: unknown): Changes {
  const b = z
    .object({ Operations: z.array(z.object({ op: z.string().min(1).max(20), path: str(200).optional(), value: z.unknown().optional() })).min(1).max(50) })
    .passthrough()
    .safeParse(body);
  if (!b.success) throw new ScimError(400, "invalidSyntax", "The request body isn't a valid SCIM PatchOp");
  const c: Changes = {};
  const apply = (key: string, value: unknown, remove: boolean) => {
    const k = key.toLowerCase();
    const text = typeof value === "string" ? value : undefined;
    if (k === "active") {
      const a = remove ? false : asBool(value);
      if (a === undefined) throw new ScimError(400, "invalidValue", "`active` must be true or false");
      c.active = a;
    } else if (k === "username") {
      if (!remove && text) c.userName = text;
    } else if (k === "externalid") {
      c.externalId = remove ? null : (text ?? null);
    } else if (k === "name.givenname") {
      c.givenName = remove ? "" : (text ?? "");
    } else if (k === "name.familyname") {
      c.familyName = remove ? "" : (text ?? "");
    } else if (k === "name" && value && typeof value === "object") {
      const n = value as Record<string, unknown>;
      if (typeof n.givenName === "string") c.givenName = n.givenName;
      if (typeof n.familyName === "string") c.familyName = n.familyName;
    } else if ((k === "emails" || k.startsWith("emails[") || k === "emails.value") && !remove) {
      const v = Array.isArray(value) ? (value[0] as { value?: unknown })?.value : (value as { value?: unknown })?.value ?? value;
      if (typeof v === "string" && v) c.userName = v;
    }
  };
  for (const op of b.data.Operations) {
    const o = op.op.toLowerCase();
    if (!["add", "replace", "remove"].includes(o)) throw new ScimError(400, "invalidSyntax", `Unsupported operation "${op.op}"`);
    if (op.path) apply(op.path, op.value, o === "remove");
    else if (op.value && typeof op.value === "object" && !Array.isArray(op.value)) for (const [k, v] of Object.entries(op.value)) apply(k, v, false);
  }
  return c;
}

// ---------- Operations ----------

function checkEmail(c: ScimCtx, raw: string) {
  const p = emailSchema.safeParse(raw);
  if (!p.success) throw new ScimError(400, "invalidValue", "userName must be an email address");
  const domain = p.data.split("@")[1];
  if (!c.domains.includes(domain)) throw new ScimError(400, "invalidValue", `${domain} isn't one of this connection's domains`);
  return p.data;
}

const setExternalId = (c: ScimCtx, userId: string, externalId: string | null) =>
  db().update(schema.scimUsers).set({ externalId }).where(and(eq(schema.scimUsers.connectionId, c.conn.id), eq(schema.scimUsers.userId, userId)));

const actor = (c: ScimCtx) => ({ type: "api" as const, id: c.conn.id });

export async function scimCreate(c: ScimCtx, body: unknown) {
  const ch = fromBody(body);
  if (!ch.userName) throw new ScimError(400, "invalidValue", "userName is required");
  const email = checkEmail(c, ch.userName);
  const idx = emailIndex(c.inst.id, email);
  const [exists] = await db().select({ id: schema.emailAddresses.id }).from(schema.emailAddresses).where(and(eq(schema.emailAddresses.instanceId, c.inst.id), eq(schema.emailAddresses.emailIndex, idx)));
  if (exists) throw new ScimError(409, "uniqueness", "A user with that userName already exists");

  const userId = newId("user");
  const emailId = newId("email");
  try {
    await db().transaction(async (tx) => {
      await tx.insert(schema.users).values({
        id: userId,
        instanceId: c.inst.id,
        firstNameEnc: encryptNullable(ch.givenName || null, `users.first_name:${userId}`),
        lastNameEnc: encryptNullable(ch.familyName || null, `users.last_name:${userId}`),
        banned: ch.active === false,
      });
      // The identity provider vouches for addresses at its own domains, so they start verified.
      await tx.insert(schema.emailAddresses).values({ id: emailId, instanceId: c.inst.id, userId, emailEnc: encrypt(email, `email_addresses.email:${emailId}`), emailIndex: idx, isPrimary: true, verifiedAt: new Date() });
      await tx.insert(schema.scimUsers).values({ connectionId: c.conn.id, userId, externalId: ch.externalId ?? null });
      if (c.conn.orgId) await tx.insert(schema.memberships).values({ orgId: c.conn.orgId, userId, role: "member" }).onConflictDoNothing();
    });
  } catch (e) {
    const code = (e as { cause?: { code?: string } }).cause?.code ?? (e as { code?: string }).code;
    if (code === "23505") throw new ScimError(409, "uniqueness", "A user with that userName already exists");
    throw e;
  }
  void emit(c.inst.id, "user.created", { userId, email });
  void record(c.inst.id, "scim_user.created", { actor: actor(c), target: userId, data: { connectionId: c.conn.id } });
  return toScim(c, userId);
}

export async function scimGet(c: ScimCtx, id: string) {
  return toScim(c, id);
}

/** Takes over a user at this connection's domain that already exists (self-signed-up or created by SAML). */
async function adopt(c: ScimCtx, emailId: string, userId: string, verified: boolean) {
  const revoked = await db().transaction(async (tx) => {
    let hashes: string[] = [];
    if (!verified) {
      // Pre-registration guard: whoever set that password never proved they own the address.
      await tx.delete(schema.passwords).where(eq(schema.passwords.userId, userId));
      await tx.update(schema.emailAddresses).set({ verifiedAt: new Date() }).where(eq(schema.emailAddresses.id, emailId));
      const rows = await tx
        .update(schema.sessions)
        .set({ status: "revoked" })
        .where(and(eq(schema.sessions.userId, userId), eq(schema.sessions.status, "active")))
        .returning({ h: schema.sessions.refreshTokenHash });
      hashes = rows.map((r) => r.h);
    }
    await tx.insert(schema.scimUsers).values({ connectionId: c.conn.id, userId }).onConflictDoNothing();
    return hashes;
  });
  if (revoked.length) await cache().del(...revoked.map((h) => `sess:${h}`));
}

export async function scimList(c: ScimCtx, q: { filter?: string; startIndex?: number; count?: number }) {
  const start = Math.max(1, Math.floor(q.startIndex ?? 1));
  const count = Math.min(MAX_PAGE, Math.max(0, Math.floor(q.count ?? 100)));
  const respond = (total: number, ids: string[]) => ({ schemas: [SCHEMAS.list], totalResults: total, startIndex: start, itemsPerPage: ids.length });

  if (q.filter) {
    const m = q.filter.match(/^\s*(userName|externalId)\s+eq\s+"((?:[^"\\]|\\.){0,300})"\s*$/i);
    if (!m) throw new ScimError(400, "invalidFilter", 'Only `userName eq "..."` and `externalId eq "..."` filters are supported');
    const value = m[2].replace(/\\(.)/g, "$1");
    let userId: string | null = null;
    if (m[1].toLowerCase() === "externalid") {
      const [l] = await db().select({ u: schema.scimUsers.userId }).from(schema.scimUsers).where(and(eq(schema.scimUsers.connectionId, c.conn.id), eq(schema.scimUsers.externalId, value)));
      userId = l?.u ?? null;
    } else {
      const email = value.trim().toLowerCase();
      const domain = email.split("@")[1];
      if (domain && c.domains.includes(domain)) {
        const [row] = await db()
          .select({ emailId: schema.emailAddresses.id, userId: schema.emailAddresses.userId, verifiedAt: schema.emailAddresses.verifiedAt })
          .from(schema.emailAddresses)
          .where(and(eq(schema.emailAddresses.instanceId, c.inst.id), eq(schema.emailAddresses.emailIndex, emailIndex(c.inst.id, email))));
        if (row) {
          // The IdP looks a person up before creating them: an account that already exists at its domain is theirs to manage.
          if ((await externalIdOf(c.conn.id, row.userId)) === undefined) await adopt(c, row.emailId, row.userId, !!row.verifiedAt);
          userId = row.userId;
        }
      }
    }
    const found = userId ? [await toScim(c, userId)] : [];
    return { ...respond(found.length, found.map((f) => f.id)), Resources: found };
  }

  const [{ n }] = (await db().select({ n: sql<number>`count(*)::int` }).from(schema.scimUsers).where(eq(schema.scimUsers.connectionId, c.conn.id))) as { n: number }[];
  const rows = count
    ? await db().select({ u: schema.scimUsers.userId }).from(schema.scimUsers).where(eq(schema.scimUsers.connectionId, c.conn.id)).orderBy(asc(schema.scimUsers.createdAt), asc(schema.scimUsers.userId)).limit(count).offset(start - 1)
    : [];
  const resources = await Promise.all(rows.map((r) => toScim(c, r.u)));
  return { ...respond(n, resources.map((r) => r.id)), Resources: resources };
}

async function apply(c: ScimCtx, userId: string, ch: Changes) {
  const before = await toScim(c, userId); // 404 unless this connection manages the user
  const set: Record<string, unknown> = {};
  if (ch.givenName !== undefined) set.firstNameEnc = encryptNullable(ch.givenName || null, `users.first_name:${userId}`);
  if (ch.familyName !== undefined) set.lastNameEnc = encryptNullable(ch.familyName || null, `users.last_name:${userId}`);
  if (Object.keys(set).length) await db().update(schema.users).set({ ...set, updatedAt: new Date() }).where(eq(schema.users.id, userId));

  if (ch.userName && ch.userName.trim().toLowerCase() !== before.userName) {
    const email = checkEmail(c, ch.userName);
    const idx = emailIndex(c.inst.id, email);
    const [taken] = await db().select({ id: schema.emailAddresses.id }).from(schema.emailAddresses).where(and(eq(schema.emailAddresses.instanceId, c.inst.id), eq(schema.emailAddresses.emailIndex, idx)));
    if (taken) throw new ScimError(409, "uniqueness", "A user with that userName already exists");
    const [primary] = await db().select({ id: schema.emailAddresses.id }).from(schema.emailAddresses).where(and(eq(schema.emailAddresses.userId, userId), eq(schema.emailAddresses.isPrimary, true)));
    if (primary) {
      try {
        await db().update(schema.emailAddresses).set({ emailEnc: encrypt(email, `email_addresses.email:${primary.id}`), emailIndex: idx, verifiedAt: new Date() }).where(eq(schema.emailAddresses.id, primary.id));
      } catch (e) {
        const code = (e as { cause?: { code?: string } }).cause?.code ?? (e as { code?: string }).code;
        if (code === "23505") throw new ScimError(409, "uniqueness", "A user with that userName already exists");
        throw e;
      }
    }
  }
  if (ch.externalId !== undefined) await setExternalId(c, userId, ch.externalId);

  if (ch.active !== undefined && ch.active !== before.active) {
    await setBanned(c.inst.id, userId, !ch.active); // suspending also signs the person out everywhere
    void record(c.inst.id, ch.active ? "scim_user.reactivated" : "scim_user.deactivated", { actor: actor(c), target: userId, data: { connectionId: c.conn.id } });
  }
  void record(c.inst.id, "scim_user.updated", { actor: actor(c), target: userId, data: { connectionId: c.conn.id } });
  return toScim(c, userId);
}

export const scimReplace = (c: ScimCtx, id: string, body: unknown) => apply(c, id, fromBody(body));
export const scimPatch = (c: ScimCtx, id: string, body: unknown) => apply(c, id, fromPatch(body));

/** The identity provider asked for the person to be removed: delete the account (only ones this connection manages). */
export async function scimDelete(c: ScimCtx, id: string) {
  if ((await externalIdOf(c.conn.id, id)) === undefined) throw new ScimError(404, undefined, "User not found");
  await deleteUser(c.inst.id, id);
  void record(c.inst.id, "scim_user.deleted", { actor: actor(c), target: id, data: { connectionId: c.conn.id } });
}

// ---------- Discovery documents ----------

export const serviceProviderConfig = (connectionId: string) => ({
  schemas: ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
  patch: { supported: true },
  bulk: { supported: false, maxOperations: 0, maxPayloadSize: 0 },
  filter: { supported: true, maxResults: MAX_PAGE },
  changePassword: { supported: false },
  sort: { supported: false },
  etag: { supported: false },
  authenticationSchemes: [{ type: "oauthbearertoken", name: "Bearer token", description: "Authentication with the connection's SCIM token", primary: true }],
  meta: { resourceType: "ServiceProviderConfig", location: `${scimBaseUrl(connectionId)}/ServiceProviderConfig` },
});

export const resourceTypes = (connectionId: string) => [
  { schemas: ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"], id: "User", name: "User", endpoint: "/Users", schema: SCHEMAS.user, meta: { resourceType: "ResourceType", location: `${scimBaseUrl(connectionId)}/ResourceTypes/User` } },
];

export const schemasDoc = (connectionId: string) => [
  { id: SCHEMAS.user, name: "User", description: "User account", attributes: [], meta: { resourceType: "Schema", location: `${scimBaseUrl(connectionId)}/Schemas/${SCHEMAS.user}` } },
];
