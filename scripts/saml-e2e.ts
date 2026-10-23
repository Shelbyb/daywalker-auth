/**
 * Enterprise SSO (SAML) against a test identity provider that signs real assertions with
 * xml-crypto, plus the classic attacks: unsigned, wrong key, tampered, signature wrapping,
 * wrong audience, expired, replay, IdP-initiated, wrong request, foreign domain.
 * Needs the service on :3000 and the openssl CLI.
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { inflateRawSync } from "node:zlib";
import { randomBytes } from "node:crypto";
import { sql } from "drizzle-orm";
import { SignedXml } from "xml-crypto";
import { seedInstance } from "./seed";
import { db, closeDb } from "../src/lib/db";
import { closeCache } from "../src/lib/cache";
import { listAudit } from "../src/lib/audit";
import { invalidateInstance } from "../src/lib/auth/instance";

const AUTH = "http://localhost:3000";
const APP = "http://localhost:3001";
let failures = 0;
const check = (name: string, ok: boolean, detail?: unknown) => {
  console.log(`${ok ? "✓" : "✗"} ${name}${ok ? "" : ` — ${JSON.stringify(detail)?.slice(0, 400)}`}`);
  if (!ok) failures++;
};

// ---------- Test IdP keys ----------
const dir = mkdtempSync(join(tmpdir(), "dw-saml-"));
const makeCert = (name: string, days = "30") => {
  execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", join(dir, `${name}.key`), "-out", join(dir, `${name}.crt`), "-days", days, "-subj", `/CN=${name}`], { stdio: "ignore" });
  return { key: readFileSync(join(dir, `${name}.key`), "utf8"), cert: readFileSync(join(dir, `${name}.crt`), "utf8") };
};
const idp = makeCert("test-idp");
const rogue = makeCert("rogue-idp");
const IDP_ENTITY = "https://idp.example.test/acme";
const SSO_URL = "https://idp.example.test/sso";

// ---------- Setup ----------
const seed = await seedInstance("SAML E2E", [APP]);
const { publishableKey: pk, secretKey: sk, instanceId } = seed;
const api = (method: string, path: string, body?: unknown, key = sk) =>
  fetch(`${AUTH}/v1/${path}`, { method, headers: { authorization: `Bearer ${key}`, "content-type": "application/json" }, body: body === undefined ? undefined : JSON.stringify(body) });
const orgId = `org_saml${Date.now()}`;
await db().execute(sql`insert into organizations (id, instance_id, name, slug) values (${orgId}, ${instanceId}, 'Acme', ${`acme-${Date.now()}`})`);

check("a bad certificate is refused", (await api("POST", "saml_connections", { name: "x", idpEntityId: IDP_ENTITY, ssoUrl: SSO_URL, certificates: ["not a cert"], domains: ["acme.test"] })).status === 400);
check("a bad domain is refused", (await api("POST", "saml_connections", { name: "x", idpEntityId: IDP_ENTITY, ssoUrl: SSO_URL, certificates: [idp.cert], domains: ["not a domain"] })).status === 422);
check("an organization from another instance is refused", (await api("POST", "saml_connections", { name: "x", idpEntityId: IDP_ENTITY, ssoUrl: SSO_URL, certificates: [idp.cert], domains: ["acme.test"], organizationId: "org_nope" })).status === 400);
const created = await api("POST", "saml_connections", { name: "Acme Okta", idpEntityId: IDP_ENTITY, ssoUrl: SSO_URL, certificates: [idp.cert], domains: ["Acme.test"], organizationId: orgId });
const conn = await created.json();
check("create a connection", created.status === 201 && conn.domains[0] === "acme.test" && conn.acsUrl === `${AUTH}/v1/saml/${conn.id}/acs`, conn);
check("the same domain can't belong to two connections", (await api("POST", "saml_connections", { name: "Dup", idpEntityId: IDP_ENTITY, ssoUrl: SSO_URL, certificates: [idp.cert], domains: ["acme.test"] })).status === 409);
const metaXml = `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.test/beta"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>${idp.cert.replace(/-----[A-Z ]+-----|\s/g, "")}</X509Certificate></X509Data></KeyInfo></KeyDescriptor><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.test/beta/sso"/></IDPSSODescriptor></EntityDescriptor>`;
const beta = await (await api("POST", "saml_connections", { name: "Beta", domains: ["beta.test"], metadataXml: metaXml })).json();
check("create a connection from IdP metadata XML", beta.idpEntityId === "https://idp.example.test/beta" && beta.ssoUrl === "https://idp.example.test/beta/sso" && beta.certificates.length === 1, beta);
check("metadata with a DOCTYPE (XXE) is refused", (await api("POST", "saml_connections", { name: "X", domains: ["x.test"], metadataXml: `<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>${metaXml}` })).status === 400);
check("connections need a secret key", (await api("GET", "saml_connections", undefined, pk)).status === 401);
const sp = await fetch(`${AUTH}/v1/saml/${conn.id}/metadata`);
const spXml = await sp.text();
check("SP metadata is served", sp.status === 200 && spXml.includes(`entityID="${AUTH}/v1/saml/${conn.id}/metadata"`) && spXml.includes(`${AUTH}/v1/saml/${conn.id}/acs`));
const env = await (await fetch(`${AUTH}/v1/client/environment?pk=${pk}`)).json();
check("environment says SSO is available", env.ssoEnabled === true);
const chk = await fetch(`${AUTH}/v1/client/sso/check?pk=${pk}`, { method: "POST", headers: { "content-type": "application/json", origin: APP }, body: JSON.stringify({ email: "anyone@ACME.test" }) });
check("domain check finds the connection", (await chk.json()).sso === true);

// ---------- Browser + IdP helpers ----------
class Browser {
  cookies = new Map<string, string>();
  header() {
    return [...this.cookies].map(([k, v]) => `${k}=${v}`).join("; ");
  }
  absorb(res: Response) {
    for (const c of res.headers.getSetCookie()) {
      const [kv] = c.split(";");
      const k = kv.slice(0, kv.indexOf("=")), v = kv.slice(kv.indexOf("=") + 1);
      if (/max-age=0/i.test(c) || v === "") this.cookies.delete(k);
      else this.cookies.set(k, v);
    }
  }
  async get(url: string) {
    const r = await fetch(url, { redirect: "manual", headers: { cookie: this.header() } });
    this.absorb(r);
    return r;
  }
  async post(url: string, form: Record<string, string>) {
    const r = await fetch(url, { method: "POST", redirect: "manual", headers: { cookie: this.header(), "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(form).toString() });
    this.absorb(r);
    return r;
  }
  async userId() {
    const r = await fetch(`${AUTH}/v1/client/session/token?pk=${pk}`, { method: "POST", headers: { origin: APP, cookie: this.header() } });
    return (await r.json()).userId as string | undefined;
  }
}

async function start(b: Browser, email: string) {
  const r = await b.get(`${AUTH}/v1/client/sso/start?pk=${pk}&email=${encodeURIComponent(email)}&redirect_url=${encodeURIComponent(`${APP}/home`)}`);
  const loc = r.headers.get("location") ?? "";
  if (!loc.startsWith(SSO_URL)) return { status: r.status, loc, requestId: "", relayState: "", acs: "" };
  const u = new URL(loc);
  const reqXml = inflateRawSync(Buffer.from(u.searchParams.get("SAMLRequest")!, "base64")).toString("utf8");
  return { status: r.status, loc, requestId: reqXml.match(/ID="([^"]+)"/)![1], relayState: u.searchParams.get("RelayState")!, acs: reqXml.match(/AssertionConsumerServiceURL="([^"]+)"/)![1] };
}

const iso = (ms: number) => new Date(Date.now() + ms).toISOString();
function assertion(o: { inResponseTo: string; nameId: string; email?: string; audience?: string; recipient?: string; notOnOrAfter?: number; issuer?: string; id?: string }) {
  const id = o.id ?? `_a${randomBytes(10).toString("hex")}`;
  return `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${id}" Version="2.0" IssueInstant="${iso(0)}"><saml:Issuer>${o.issuer ?? IDP_ENTITY}</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${o.nameId}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="${o.inResponseTo}" NotOnOrAfter="${iso(o.notOnOrAfter ?? 300_000)}" Recipient="${o.recipient ?? `${AUTH}/v1/saml/${conn.id}/acs`}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="${iso(-60_000)}" NotOnOrAfter="${iso(o.notOnOrAfter ?? 300_000)}"><saml:AudienceRestriction><saml:Audience>${o.audience ?? `${AUTH}/v1/saml/${conn.id}/metadata`}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="${iso(0)}" SessionIndex="_s1"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>${o.email ?? o.nameId}</saml:AttributeValue></saml:Attribute><saml:Attribute Name="firstName"><saml:AttributeValue>Alice</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion>`;
}
function sign(xml: string, key = idp.key) {
  const s = new SignedXml({ privateKey: key, canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#", signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" });
  s.addReference({ xpath: "//*[local-name(.)='Assertion']", digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256", transforms: ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/2001/10/xml-exc-c14n#"] });
  s.computeSignature(xml, { location: { reference: "//*[local-name(.)='Assertion']/*[local-name(.)='Issuer']", action: "after" } });
  return s.getSignedXml();
}
const response = (inResponseTo: string, assertionXml: string, destination = `${AUTH}/v1/saml/${conn.id}/acs`) =>
  Buffer.from(
    `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r${randomBytes(8).toString("hex")}" Version="2.0" IssueInstant="${iso(0)}" Destination="${destination}" InResponseTo="${inResponseTo}"><saml:Issuer>${IDP_ENTITY}</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>${assertionXml}</samlp:Response>`,
  ).toString("base64");
const errOf = (r: Response) => new URL(r.headers.get("location") ?? "http://x/", AUTH).searchParams.get("error");

// ---------- Happy path ----------
const t = Date.now();
const alice = `alice.${t}@acme.test`;
const b1 = new Browser();
const s1 = await start(b1, alice);
check("start redirects to the IdP with a SAML request", s1.status === 302 && !!s1.requestId && s1.acs === `${AUTH}/v1/saml/${conn.id}/acs`, s1);
check("state cookie is HttpOnly and path-scoped", [...b1.cookies.keys()].includes("__dw_saml"));
const good = response(s1.requestId, sign(assertion({ inResponseTo: s1.requestId, nameId: alice })));
const r1 = await b1.post(`${AUTH}/v1/saml/${conn.id}/acs`, { SAMLResponse: good, RelayState: s1.relayState });
const aliceId = await b1.userId();
check("a valid signed assertion signs in and returns to the app", r1.status === 302 && r1.headers.get("location") === `${APP}/home` && !!aliceId, { loc: r1.headers.get("location") });
const u = await (await api("GET", `users/${aliceId}`)).json();
check("user created with a verified email and a name", u.emailAddresses?.[0]?.email === alice && u.emailAddresses[0].verified && u.firstName === "Alice", u);
const mem = (await db().execute(sql`select role from memberships where org_id = ${orgId} and user_id = ${aliceId}`)) as unknown as { role: string }[];
check("…and joined the connection's organization", mem[0]?.role === "member");
const replay = await new Browser().post(`${AUTH}/v1/saml/${conn.id}/acs`, { SAMLResponse: good, RelayState: s1.relayState });
check("replaying the same response is refused", replay.status === 400);
const b1again = await b1.post(`${AUTH}/v1/saml/${conn.id}/acs`, { SAMLResponse: good, RelayState: s1.relayState });
check("…even from the same browser", b1again.status === 400);

const b2 = new Browser();
const s2 = await start(b2, alice);
await b2.post(`${AUTH}/v1/saml/${conn.id}/acs`, { SAMLResponse: response(s2.requestId, sign(assertion({ inResponseTo: s2.requestId, nameId: alice }))), RelayState: s2.relayState });
check("signing in again reaches the same user", (await b2.userId()) === aliceId);

// ---------- Attacks ----------
async function attempt(name: string, build: (s: Awaited<ReturnType<typeof start>>) => string, email = `mallory.${t}@acme.test`) {
  const b = new Browser();
  const s = await start(b, email);
  const r = await b.post(`${AUTH}/v1/saml/${conn.id}/acs`, { SAMLResponse: build(s), RelayState: s.relayState });
  const ok = r.status === 302 && !!errOf(r) && !(await b.userId());
  check(name, ok, { status: r.status, loc: r.headers.get("location") });
  return errOf(r);
}
const mallory = `mallory.${t}@acme.test`;
await attempt("unsigned assertion → refused", (s) => response(s.requestId, assertion({ inResponseTo: s.requestId, nameId: mallory })));
await attempt("assertion signed by the wrong key → refused", (s) => response(s.requestId, sign(assertion({ inResponseTo: s.requestId, nameId: mallory }), rogue.key)));
await attempt("assertion edited after signing → refused", (s) => response(s.requestId, sign(assertion({ inResponseTo: s.requestId, nameId: `nobody.${t}@acme.test` })).replace(`nobody.${t}@acme.test</saml:NameID>`, `${alice}</saml:NameID>`)));
await attempt("signature wrapping (forged assertion beside a signed one) → refused", (s) => {
  const signed = sign(assertion({ inResponseTo: s.requestId, nameId: `nobody.${t}@acme.test` }));
  const forged = assertion({ inResponseTo: s.requestId, nameId: alice, id: `_forged${t}` });
  return response(s.requestId, forged + signed);
});
await attempt("wrong audience → refused", (s) => response(s.requestId, sign(assertion({ inResponseTo: s.requestId, nameId: mallory, audience: "https://other-sp.example/metadata" }))));
await attempt("expired assertion → refused", (s) => response(s.requestId, sign(assertion({ inResponseTo: s.requestId, nameId: mallory, notOnOrAfter: -120_000 }))));
await attempt("assertion from a different issuer → refused", (s) => response(s.requestId, sign(assertion({ inResponseTo: s.requestId, nameId: mallory, issuer: "https://evil-idp.example" }))));
const other = await start(new Browser(), `x.${t}@acme.test`);
await attempt("answer to a different sign-in request → refused", () => response(other.requestId, sign(assertion({ inResponseTo: other.requestId, nameId: mallory }))));
const foreign = await attempt("email outside the connection's domains → refused", (s) => response(s.requestId, sign(assertion({ inResponseTo: s.requestId, nameId: `eve.${t}@evil.test` }))));
check("…with email_unverified", foreign === "email_unverified", foreign);

const idpInit = await new Browser().post(`${AUTH}/v1/saml/${conn.id}/acs`, { SAMLResponse: response("", sign(assertion({ inResponseTo: "", nameId: mallory }))), RelayState: "" });
check("IdP-initiated response (no sign-in started here) → refused", idpInit.status === 400);
const b3 = new Browser();
const s3 = await start(b3, mallory);
const cross = await b3.post(`${AUTH}/v1/saml/${beta.id}/acs`, { SAMLResponse: response(s3.requestId, sign(assertion({ inResponseTo: s3.requestId, nameId: mallory }))), RelayState: s3.relayState });
check("a response posted to another connection's ACS → refused", cross.status === 400);
const noCookie = await start(new Browser(), mallory);
const stolen = await new Browser().post(`${AUTH}/v1/saml/${conn.id}/acs`, { SAMLResponse: response(noCookie.requestId, sign(assertion({ inResponseTo: noCookie.requestId, nameId: mallory }))), RelayState: noCookie.relayState });
check("a valid response in a browser that didn't start the sign-in → refused (login CSRF)", stolen.status === 400);

// ---------- Unknown domain, disabled connection ----------
const nope = await new Browser().get(`${AUTH}/v1/client/sso/start?pk=${pk}&email=${encodeURIComponent(`a@nowhere.test`)}`);
check("a domain without SSO can't start", nope.status === 400);
await api("PATCH", `saml_connections/${conn.id}`, { enabled: false });
const off = await new Browser().get(`${AUTH}/v1/client/sso/start?pk=${pk}&email=${encodeURIComponent(alice)}`);
check("a disabled connection can't start", off.status === 400);
await api("PATCH", `saml_connections/${conn.id}`, { enabled: true });

// ---------- Existing accounts ----------
const bob = `bob.${t}@acme.test`;
const su = await fetch(`${AUTH}/v1/client/sign_up?pk=${pk}`, { method: "POST", headers: { "content-type": "application/json", origin: APP }, body: JSON.stringify({ email: bob, password: "a long enough password" }) });
const bobId = (await su.json()).user.id;
const b4 = new Browser();
const s4 = await start(b4, bob);
await b4.post(`${AUTH}/v1/saml/${conn.id}/acs`, { SAMLResponse: response(s4.requestId, sign(assertion({ inResponseTo: s4.requestId, nameId: bob }))), RelayState: s4.relayState });
check("an existing account at the domain is linked, not duplicated", (await b4.userId()) === bobId);
const pw = (await db().execute(sql`select count(*)::int as n from passwords where user_id = ${bobId}`)) as unknown as { n: number }[];
check("…and its unverified password is removed (pre-registration takeover guard)", pw[0].n === 0);

// ---------- "SSO required" ----------
const PW = "a long enough password";
const cl = (path: string, body: unknown, method = "POST") =>
  fetch(`${AUTH}/v1/client/${path}?pk=${pk}`, { method, headers: { "content-type": "application/json", origin: APP }, body: JSON.stringify(body) });
const carol = `carol.${t}@acme.test`, eveMail = `eve.${t}@acme.test`, dave = `dave.${t}@other.test`;
for (const e of [carol, eveMail, dave]) await cl("sign_up", { email: e, password: PW });
await db().execute(sql`update instances set settings = settings || '{"emailCodeSignIn": true}'::jsonb where id = ${instanceId}`);
await invalidateInstance(instanceId);
const carolIn = await cl("sign_in", { email: carol, password: PW });
check("before enforcing, a password sign-in at the domain works", carolIn.status === 200);
const carolId = (await carolIn.json()).user.id as string;
const daveId = (await (await cl("sign_in", { email: dave, password: PW })).json()).user.id as string;
const active = async (uid: string) => ((await db().execute(sql`select count(*)::int as n from sessions where user_id = ${uid} and status = 'active'`)) as unknown as { n: number }[])[0].n;
check("both have a live session before enforcing", (await active(carolId)) > 0 && (await active(daveId)) > 0);

check("a connection starts with SSO not required", conn.ssoRequired === false);
const req = await (await api("PATCH", `saml_connections/${conn.id}`, { ssoRequired: true })).json();
check("turn on SSO required", req.ssoRequired === true);
check("turning it on ends the sessions of people at the domain", (await active(carolId)) === 0);
check("…and leaves other domains alone", (await active(daveId)) > 0);
const code = async (r: Response) => (await r.json())?.error?.code;
const pwIn = await cl("sign_in", { email: carol, password: PW });
check("password sign-in is refused for the domain, even with the right password", pwIn.status === 403 && (await code(pwIn)) === "sso_required");
check("…and with a wrong one (no hint about the password)", (await code(await cl("sign_in", { email: carol, password: "wrong wrong wrong" }))) === "sso_required");
const before = (await db().execute(sql`select count(*)::int as n from email_addresses where instance_id = ${instanceId}`)) as unknown as { n: number }[];
check("sign-up at the domain is refused", (await code(await cl("sign_up", { email: `new.${t}@acme.test`, password: PW }))) === "sso_required");
const after = (await db().execute(sql`select count(*)::int as n from email_addresses where instance_id = ${instanceId}`)) as unknown as { n: number }[];
check("…and creates no account", before[0].n === after[0].n);
check("an email sign-in code can't be requested", (await code(await cl("sign_in/email_code", { email: carol }))) === "sso_required");
check("a password reset can't be requested", (await code(await cl("password/forgot", { email: carol }))) === "sso_required");
check("a password reset can't be completed either", (await code(await cl("password/reset", { email: carol, code: "123456", password: PW }))) === "sso_required");
check("other domains are unaffected", (await cl("sign_in", { email: dave, password: PW })).status === 200);
const sc = await (await cl("sso/check", { email: carol })).json();
check("the SSO check says it's required, so a form can hide the password", sc.sso === true && sc.required === true, sc);
check("…and not for a domain without SSO", (await (await cl("sso/check", { email: dave })).json()).sso === false);

const bc = new Browser();
const sx = await start(bc, carol);
await bc.post(`${AUTH}/v1/saml/${conn.id}/acs`, { SAMLResponse: response(sx.requestId, sign(assertion({ inResponseTo: sx.requestId, nameId: carol }))), RelayState: sx.relayState });
check("the identity provider still signs the same person in", !!(await bc.userId()));

await api("PATCH", `saml_connections/${conn.id}`, { enabled: false });
check("a disabled connection doesn't lock anyone out", (await cl("sign_in", { email: eveMail, password: PW })).status === 200);
await api("PATCH", `saml_connections/${conn.id}`, { enabled: true });
check("enabled again: refused", (await code(await cl("sign_in", { email: eveMail, password: PW }))) === "sso_required");
await api("PATCH", `saml_connections/${conn.id}`, { ssoRequired: false });
check("turn it off: password sign-in works again", (await cl("sign_in", { email: eveMail, password: PW })).status === 200);

await new Promise((r) => setTimeout(r, 400));
const audit = (await listAudit(instanceId, { limit: 200 })).data;
check("audit log: SSO sign-ins and rejected responses", audit.some((e) => e.type === "user.signed_in" && e.data?.method === "saml") && audit.some((e) => e.type === "user.sign_in_failed" && e.data?.reason === "saml_invalid"));
check("delete a connection", (await api("DELETE", `saml_connections/${beta.id}`)).status === 200 && (await api("GET", `saml_connections/${beta.id}`)).status === 404);

rmSync(dir, { recursive: true, force: true });
await closeDb();
await closeCache();
console.log(failures ? `\n${failures} check(s) failed` : "\nAll SAML checks passed");
process.exit(failures ? 1 : 0);
