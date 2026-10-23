/**
 * SAML single logout (SLO), both directions.
 *
 * - IdP-initiated: the identity provider sends a signed LogoutRequest to /v1/saml/{id}/slo. Every
 *   session that came from that person's sign-in through this connection is revoked, and we answer
 *   with a signed LogoutResponse.
 * - SP-initiated (opt-in per connection): signing out of the app sends the browser to the identity
 *   provider with a signed LogoutRequest; its LogoutResponse comes back to /slo and we redirect on.
 *
 * Checks on every incoming message, on top of @node-saml/node-saml:
 * - A signature is REQUIRED. (The library accepts unsigned HTTP-Redirect messages, so the redirect
 *   signature is verified here, from the raw query string, with exact parameter matching.)
 * - Issuer must be the connection's IdP, Destination (if present) must be our SLO URL, IssueInstant
 *   must be recent, and each message ID is accepted once.
 * - A LogoutResponse must answer a LogoutRequest we sent (single use), and only then do we use the
 *   redirect we stored for it. The person is already signed out locally whatever happens.
 */
import { createVerify, X509Certificate } from "node:crypto";
import { inflateRawSync } from "node:zlib";
import { stringify } from "node:querystring";
import { and, eq, inArray } from "drizzle-orm";
import { DOMParser } from "@xmldom/xmldom";
import type { Profile } from "@node-saml/node-saml";
import { db, schema } from "../db";
import { cache, rateLimit } from "../cache";
import { blindIndex, decrypt, decryptNullable, encrypt, encryptNullable } from "../crypto";
import { env } from "../env";
import { newToken, sha256 } from "../ids";
import { record } from "../audit";
import { connectionById, ensureSpKey, samlFor, sloCallbackUrl, type Connection, type SamlLogin } from "./saml";
import { publishableKey, getInstance } from "./instance";

const SLO_TTL = 600;
const MAX_AGE_MS = 10 * 60_000;
const SKEW_MS = 60_000;

const nameIndex = (connectionId: string, nameID: string) => blindIndex(nameID, `saml_nameid:${connectionId}`);

// ---------- Remembering which sign-in a session came from ----------

export async function linkSamlSession(sessionId: string, login: SamlLogin) {
  await db()
    .insert(schema.samlSessions)
    .values({
      sessionId,
      connectionId: login.connectionId,
      nameIdEnc: encrypt(login.nameID, `saml_sessions.name_id:${sessionId}`),
      nameIdIndex: nameIndex(login.connectionId, login.nameID),
      nameIdFormat: login.nameIDFormat,
      sessionIndexEnc: encryptNullable(login.sessionIndex, `saml_sessions.session_index:${sessionId}`),
    })
    .onConflictDoNothing();
}

/** When the account has two-factor, the session only exists after the second step: carry the login across. */
const pendingKey = (token: string) => `saml:2fa:${sha256(token)}`;
export async function stashForSecondFactor(token: string, login: SamlLogin) {
  await cache().set(pendingKey(token), encrypt(JSON.stringify(login), "saml_2fa"), "EX", SLO_TTL);
}
export async function linkAfterSecondFactor(token: string | undefined, sessionId: string) {
  if (!token) return;
  const raw = await cache().getdel(pendingKey(token));
  if (raw) await linkSamlSession(sessionId, JSON.parse(decrypt(raw, "saml_2fa")) as SamlLogin);
}

/** Session IDs (of these) that came from a SAML sign-in: "SSO required" leaves them alone. */
export async function samlSessionIds(sessionIds: string[]) {
  if (!sessionIds.length) return new Set<string>();
  const rows = await db().select({ id: schema.samlSessions.sessionId }).from(schema.samlSessions).where(inArray(schema.samlSessions.sessionId, sessionIds));
  return new Set(rows.map((r) => r.id));
}

// ---------- Incoming message checks ----------

const SIG_ALGS: Record<string, string> = {
  "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256": "RSA-SHA256",
  "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512": "RSA-SHA512",
  "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256": "SHA256",
};

/**
 * HTTP-Redirect binding (SAML bindings §3.4.4.1): the signature covers `SAMLRequest|SAMLResponse`,
 * `RelayState` and `SigAlg` as URL-encoded by the sender. The framework hands us a re-encoded query
 * (a space arrives as "+"), and identity providers differ (ADFS uses lowercase hex), so we check the
 * DECODED values under each common encoding. Changing any value still breaks the signature.
 */
function redirectSignatureValid(query: URLSearchParams, certs: string[]) {
  const one = (k: string) => {
    const all = query.getAll(k);
    return all.length > 1 ? null : (all[0] ?? undefined); // null: duplicated (refuse)
  };
  const req = one("SAMLRequest"), res = one("SAMLResponse"), relay = one("RelayState"), alg = one("SigAlg"), sig = one("Signature");
  if (req === null || res === null || relay === null || alg === null || sig === null) return false;
  if (!alg || !sig || (req === undefined) === (res === undefined)) return false;
  const nodeAlg = SIG_ALGS[alg];
  if (!nodeAlg) return false;
  const encoders = [
    (v: string) => encodeURIComponent(v),
    (v: string) => encodeURIComponent(v).replace(/%20/g, "+"),
    (v: string) => encodeURIComponent(v).replace(/%[0-9A-F]{2}/g, (m) => m.toLowerCase()),
  ];
  const signature = Buffer.from(sig, "base64");
  const keys = certs.flatMap((b64) => {
    try {
      return [new X509Certificate(Buffer.from(b64, "base64")).publicKey];
    } catch {
      return [];
    }
  });
  return encoders.some((enc) => {
    const signed = [req !== undefined ? `SAMLRequest=${enc(req)}` : `SAMLResponse=${enc(res!)}`, relay !== undefined ? `RelayState=${enc(relay)}` : null, `SigAlg=${enc(alg)}`].filter(Boolean).join("&");
    return keys.some((k) => {
      try {
        return createVerify(nodeAlg).update(signed).verify(k, signature);
      } catch {
        return false;
      }
    });
  });
}

type Parsed = { kind: "LogoutRequest" | "LogoutResponse"; id: string; inResponseTo: string | null };

/** Our own checks on the XML: issuer, destination, freshness, and one use per message ID. */
async function checkMessage(c: Connection, xml: string): Promise<Parsed> {
  if (xml.length > 100_000 || /<!DOCTYPE|<!ENTITY/i.test(xml)) throw new Error("bad message");
  const root = new DOMParser().parseFromString(xml, "text/xml").documentElement;
  const kind = root?.localName;
  if (kind !== "LogoutRequest" && kind !== "LogoutResponse") throw new Error("not a logout message");
  const id = root.getAttribute("ID") ?? "";
  if (!id || id.length > 200) throw new Error("missing ID");
  const issuer = Array.from(root.childNodes).find((n) => (n as Element).localName === "Issuer")?.textContent?.trim();
  if (issuer !== c.idpEntityId) throw new Error("issuer mismatch");
  const dest = root.getAttribute("Destination");
  if (dest && dest !== sloCallbackUrl(c.id)) throw new Error("wrong destination");
  const at = Date.parse(root.getAttribute("IssueInstant") ?? "");
  if (!Number.isFinite(at) || at > Date.now() + SKEW_MS || at < Date.now() - MAX_AGE_MS) throw new Error("stale or future message");
  if (!(await cache().set(`saml:slo:seen:${c.id}:${sha256(id)}`, "1", "EX", Math.ceil((MAX_AGE_MS + SKEW_MS) / 1000), "NX"))) throw new Error("replayed message");
  return { kind, id, inResponseTo: root.getAttribute("InResponseTo") };
}

/**
 * The library signs `querystring.stringify(...)` but builds the URL with URLSearchParams, which encodes
 * some characters differently (a space is "+" instead of "%20"). Rebuild the query the way it was signed,
 * so identity providers that check the raw query string accept it.
 */
function signedRedirect(url: string) {
  const u = new URL(url);
  const p = u.searchParams;
  const ordered: Record<string, string> = {};
  for (const k of ["SAMLRequest", "SAMLResponse", "RelayState", "SigAlg", "Signature"]) if (p.has(k)) ordered[k] = p.get(k)!;
  for (const k of Object.keys(ordered)) p.delete(k);
  const rest = u.search.slice(1); // the IdP URL's own query parameters, untouched
  u.search = [rest, stringify(ordered)].filter(Boolean).join("&");
  return u.toString();
}

// ---------- Endpoint ----------

type SloResult = { status: number; location?: string; text?: string };

/**
 * One handler for both bindings and both message types: `query` for HTTP-Redirect, `form` for HTTP-POST.
 */
export async function handleSlo(connectionId: string, query: URLSearchParams, form: FormData | null): Promise<SloResult> {
  const c = await connectionById(connectionId);
  if (!c) return { status: 404, text: "Unknown SSO connection" };
  if ((await rateLimit(`saml_slo:${c.id}`, 300, 60)) < 0) return { status: 429, text: "Too many requests" };
  const field = (k: string) => (form ? (typeof form.get(k) === "string" ? (form.get(k) as string) : null) : query.get(k));
  const samlRequest = field("SAMLRequest"), samlResponse = field("SAMLResponse");
  const relayState = (field("RelayState") ?? "").slice(0, 500);
  const encoded = samlRequest ?? samlResponse;
  if (!encoded || (samlRequest && samlResponse) || encoded.length > 200_000) return { status: 400, text: "Missing SAML message" };

  let xml: string;
  try {
    const bytes = Buffer.from(encoded, "base64");
    xml = form ? bytes.toString("utf8") : inflateRawSync(bytes, { maxOutputLength: 100_000 }).toString("utf8");
  } catch {
    return { status: 400, text: "Unreadable SAML message" };
  }

  let parsed: Parsed;
  let profile: Profile | null = null;
  try {
    parsed = await checkMessage(c, xml);
    if ((parsed.kind === "LogoutRequest") !== !!samlRequest) throw new Error("message type mismatch");
    const saml = samlFor(c);
    if (form) {
      // XML signature on the whole message (the library refuses unsigned POST messages).
      if (samlRequest) ({ profile } = await saml.validatePostRequestAsync({ SAMLRequest: samlRequest }));
      else await saml.validatePostResponseAsync({ SAMLResponse: samlResponse! });
    } else {
      if (!redirectSignatureValid(query, c.certificates)) throw new Error("missing or invalid signature");
      // Signature checked above; the library then only parses and checks issuer, times and InResponseTo.
      const container: Record<string, string> = samlRequest ? { SAMLRequest: samlRequest } : { SAMLResponse: samlResponse! };
      ({ profile } = await saml.validateRedirectAsync(container, ""));
    }
  } catch (e) {
    void record(c.instanceId, "user.sign_in_failed", { target: null, data: { reason: "saml_slo_invalid", connectionId: c.id, detail: String((e as Error).message).slice(0, 120) } });
    // A bad response to our own logout still lands the person somewhere sensible (they're signed out here already).
    if (samlResponse) return { status: 302, location: await afterLogout(c, null) };
    return { status: 400, text: "This logout request couldn't be verified" };
  }

  if (parsed.kind === "LogoutResponse") return { status: 302, location: await afterLogout(c, parsed.inResponseTo) };

  // IdP-initiated: end every session from this person's sign-ins through this connection.
  const nameID = profile?.nameID;
  if (!nameID) return { status: 400, text: "The logout request didn't say who to sign out" };
  const ended = await endSessionsFor(c, nameID);
  void record(c.instanceId, "user.signed_out", { actor: { type: "api", id: c.id }, target: ended.userIds[0] ?? null, data: { reason: "saml_single_logout", connectionId: c.id, sessions: ended.count } });
  if (!c.sloUrl) return { status: 200, text: "Signed out" };
  const { privateKey } = await ensureSpKey(c);
  const location = signedRedirect(await samlFor(c, { privateKey }).getLogoutResponseUrlAsync(profile!, relayState, {}, true));
  return { status: 302, location };
}

async function endSessionsFor(c: Connection, nameID: string) {
  const links = await db()
    .select({ id: schema.samlSessions.sessionId })
    .from(schema.samlSessions)
    .where(and(eq(schema.samlSessions.connectionId, c.id), eq(schema.samlSessions.nameIdIndex, nameIndex(c.id, nameID))));
  if (!links.length) return { count: 0, userIds: [] as string[] };
  const rows = await db()
    .update(schema.sessions)
    .set({ status: "revoked" })
    .where(and(inArray(schema.sessions.id, links.map((l) => l.id)), eq(schema.sessions.status, "active")))
    .returning({ h: schema.sessions.refreshTokenHash, userId: schema.sessions.userId });
  if (rows.length) await cache().del(...rows.map((r) => `sess:${r.h}`));
  return { count: rows.length, userIds: [...new Set(rows.map((r) => r.userId))] };
}

/** Where the browser goes after the identity provider answers our logout request. */
async function afterLogout(c: Connection, inResponseTo: string | null) {
  const raw = inResponseTo ? await cache().getdel(`saml:slo:req:${sha256(inResponseTo)}`) : null;
  const stored = raw ? (JSON.parse(decrypt(raw, "saml_slo")) as { connectionId: string; redirect: string | null }) : null;
  if (stored?.connectionId === c.id && stored.redirect) return stored.redirect;
  const inst = await getInstance(c.instanceId);
  return `${env().APP_URL}/sign-in${inst ? `?pk=${encodeURIComponent(publishableKey(inst))}` : ""}`;
}

// ---------- SP-initiated ----------

/**
 * Called on sign-out, before the session ends. If the session came from a connection with single
 * logout turned on, returns the identity provider URL to send the browser to (a signed LogoutRequest).
 * `redirect` must already be validated against the instance's allowed origins.
 */
export async function startSingleLogout(instanceId: string, refreshToken: string, redirect: string | null) {
  const [s] = await db()
    .select({ id: schema.sessions.id })
    .from(schema.sessions)
    .where(and(eq(schema.sessions.refreshTokenHash, sha256(refreshToken)), eq(schema.sessions.instanceId, instanceId)));
  if (!s) return null;
  const [link] = await db().select().from(schema.samlSessions).where(eq(schema.samlSessions.sessionId, s.id));
  if (!link) return null;
  const c = await connectionById(link.connectionId);
  if (!c || c.instanceId !== instanceId || !c.singleLogout || !c.sloUrl) return null;
  const requestId = `_${newToken(20)}`;
  await cache().set(`saml:slo:req:${sha256(requestId)}`, encrypt(JSON.stringify({ connectionId: c.id, redirect }), "saml_slo"), "EX", SLO_TTL);
  const { privateKey } = await ensureSpKey(c);
  const user = {
    issuer: c.idpEntityId,
    nameID: decrypt(link.nameIdEnc, `saml_sessions.name_id:${s.id}`),
    nameIDFormat: link.nameIdFormat ?? "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
    sessionIndex: decryptNullable(link.sessionIndexEnc, `saml_sessions.session_index:${s.id}`) ?? undefined,
  } as Profile;
  return signedRedirect(await samlFor(c, { requestId, privateKey }).getLogoutUrlAsync(user, "", {}));
}
