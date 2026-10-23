/**
 * SCIM 2.0 provisioning: create, read, filter, update, deactivate and delete through the same
 * calls an identity provider (Okta, Entra ID) makes, plus the ways it could go wrong.
 * Needs the service on :3000 and the openssl CLI.
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomInt } from "node:crypto";
import { sql } from "drizzle-orm";
import { seedInstance } from "./seed";
import { db, closeDb } from "../src/lib/db";
import { closeCache } from "../src/lib/cache";
import { listAudit } from "../src/lib/audit";

const AUTH = "http://localhost:3000";
const SCHEMA_GROUP = "urn:ietf:params:scim:schemas:core:2.0:Group";
let failures = 0;
const check = (name: string, ok: boolean, detail?: unknown) => {
  console.log(`${ok ? "✓" : "✗"} ${name}${ok ? "" : ` — ${JSON.stringify(detail)?.slice(0, 400)}`}`);
  if (!ok) failures++;
};

// A certificate for the connection (never used to sign anything here).
const dir = mkdtempSync(join(tmpdir(), "dw-scim-"));
execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", join(dir, "k.pem"), "-out", join(dir, "c.pem"), "-days", "30", "-subj", "/CN=scim-test"], { stdio: "ignore" });
const cert = readFileSync(join(dir, "c.pem"), "utf8");
rmSync(dir, { recursive: true, force: true });

const seed = await seedInstance("SCIM E2E", []);
const { instanceId, secretKey: sk, publishableKey: pk } = seed;
const api = (method: string, path: string, body?: unknown) =>
  fetch(`${AUTH}/v1/${path}`, { method, headers: { authorization: `Bearer ${sk}`, "content-type": "application/json" }, body: body === undefined ? undefined : JSON.stringify(body) });
const t = Date.now();
const orgId = `org_scim${t}`;
await db().execute(sql`insert into organizations (id, instance_id, name, slug) values (${orgId}, ${instanceId}, 'Acme', ${`acme-${t}`})`);
const mk = async (name: string, domain: string, organizationId?: string) =>
  (await (await api("POST", "saml_connections", { name, idpEntityId: `https://idp.example.test/${name}`, ssoUrl: "https://idp.example.test/sso", certificates: [cert], domains: [domain], ...(organizationId ? { organizationId } : {}) })).json()) as { id: string; scim: { enabled: boolean; baseUrl: string } };
const conn = await mk("Acme", "acme.test", orgId);
const other = await mk("Other", "other-co.test");

const call = (token: string | null, method: string, path: string, body?: unknown, c = conn.id, raw?: string) =>
  fetch(`${AUTH}/v1/scim/v2/${c}/${path}`, {
    method,
    headers: { "content-type": "application/scim+json", ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: raw ?? (body === undefined ? undefined : JSON.stringify(body)),
  });
const j = async (r: Response) => (await r.json().catch(() => null)) as Record<string, any> | null;

// ---------- Token ----------
check("provisioning starts off", conn.scim.enabled === false);
const noTok = await call(null, "GET", "Users");
const noTokBody = await j(noTok);
check("no token → 401 in SCIM's error format", noTok.status === 401 && noTok.headers.get("content-type")?.includes("scim+json") === true && noTokBody?.schemas?.[0] === "urn:ietf:params:scim:api:messages:2.0:Error" && noTokBody.status === "401", noTokBody);
check("a made-up token → 401", (await call("scim_" + "a".repeat(43), "GET", "Users")).status === 401);
const made = await (await api("POST", `saml_connections/${conn.id}/scim_token`)).json();
const TOKEN: string = made.token;
check("turning provisioning on returns the token once, and the base URL", /^scim_[A-Za-z0-9_-]{40,}$/.test(TOKEN) && made.baseUrl === `${AUTH}/v1/scim/v2/${conn.id}`, made);
const view = await (await api("GET", `saml_connections/${conn.id}`)).json();
check("reading the connection never shows the token or its hash", view.scim.enabled === true && !JSON.stringify(view).includes(TOKEN) && !JSON.stringify(view).includes("scimTokenHash"), view.scim);
const stored = (await db().execute(sql`select scim_token_hash as h from saml_connections where id = ${conn.id}`)) as unknown as { h: string }[];
check("only a hash is stored", stored[0].h !== TOKEN && /^[0-9a-f]{64}$/.test(stored[0].h) && !stored[0].h.includes(TOKEN.slice(5, 20)));
check("the token doesn't work for another connection", (await call(TOKEN, "GET", "Users", undefined, other.id)).status === 401);
check("a token with the wrong shape is refused", (await call("Bearer x", "GET", "Users")).status === 401);
for (const p of ["ServiceProviderConfig", "ResourceTypes", "Schemas"]) {
  const r = await call(TOKEN, "GET", p);
  check(`${p} answers`, r.status === 200, r.status);
}
check("discovery needs the token too", (await call(null, "GET", "ServiceProviderConfig")).status === 401);

// ---------- Create ----------
const alice = `alice.${t}@acme.test`;
const created = await call(TOKEN, "POST", "Users", { schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"], userName: alice, externalId: "okta-1", name: { givenName: "Alice", familyName: "Ng" }, emails: [{ value: alice, primary: true }], active: true });
const a = await j(created);
check("create → 201 with a SCIM User", created.status === 201 && /^user_/.test(a?.id) && a?.userName === alice && a?.externalId === "okta-1" && a?.active === true && a?.name?.givenName === "Alice" && a?.meta?.resourceType === "User", a);
const row = (await db().execute(sql`select e.email_enc as enc, e.verified_at as v, (select count(*)::int from passwords where user_id = ${a?.id}) as pw, (select count(*)::int from memberships where org_id = ${orgId} and user_id = ${a?.id}) as m from email_addresses e where e.user_id = ${a?.id}`)) as unknown as { enc: string; v: string | null; pw: number; m: number }[];
check("the address is encrypted, already verified, there's no password, and they joined the organization", row[0].enc !== alice && !row[0].enc.includes("alice") && !!row[0].v && row[0].pw === 0 && row[0].m === 1, row[0]);
const dupe = await call(TOKEN, "POST", "Users", { userName: alice });
check("creating the same person again → 409 uniqueness", dupe.status === 409 && (await j(dupe))?.scimType === "uniqueness");
const dupeCase = await call(TOKEN, "POST", "Users", { userName: alice.toUpperCase() });
check("…even in different letters", dupeCase.status === 409);
const foreign = await call(TOKEN, "POST", "Users", { userName: `eve.${t}@evil.test` });
check("an address outside the connection's domains → 400 invalidValue", foreign.status === 400 && (await j(foreign))?.scimType === "invalidValue");
check("no userName → 400", (await call(TOKEN, "POST", "Users", { name: { givenName: "x" } })).status === 400);
check("garbage JSON → 400", (await call(TOKEN, "POST", "Users", undefined, conn.id, "{nope")).status === 400);
check("an enormous body → 413", (await call(TOKEN, "POST", "Users", undefined, conn.id, JSON.stringify({ userName: "x".repeat(70_000) }))).status === 413);
check("an email at the domain, made by emails[] only, works", (await call(TOKEN, "POST", "Users", { emails: [{ value: `emma.${t}@acme.test`, primary: true }] })).status === 201);

// ---------- Read, list, filter ----------
const got = await call(TOKEN, "GET", `Users/${a!.id}`);
check("read one", got.status === 200 && (await j(got))?.userName === alice);
check("an unknown ID → 404", (await call(TOKEN, "GET", "Users/user_nope")).status === 404);
const fl = await j(await call(TOKEN, "GET", `Users?filter=${encodeURIComponent(`userName eq "${alice}"`)}`));
check("filter by userName", fl?.totalResults === 1 && fl.Resources[0].id === a!.id && fl.schemas[0].endsWith("ListResponse"), fl);
check("filter by externalId", (await j(await call(TOKEN, "GET", `Users?filter=${encodeURIComponent('externalId eq "okta-1"')}`)))?.totalResults === 1);
check("a filter that matches nobody is an empty list, not an error", (await j(await call(TOKEN, "GET", `Users?filter=${encodeURIComponent('userName eq "nobody@acme.test"')}`)))?.totalResults === 0);
const bad = await call(TOKEN, "GET", `Users?filter=${encodeURIComponent('userName co "a"')}`);
check("an unsupported filter → 400 invalidFilter", bad.status === 400 && (await j(bad))?.scimType === "invalidFilter");
await call(TOKEN, "POST", "Users", { userName: `fred.${t}@acme.test` });
const page = await j(await call(TOKEN, "GET", "Users?startIndex=2&count=1"));
check("pagination", page?.totalResults === 3 && page.itemsPerPage === 1 && page.startIndex === 2 && page.Resources.length === 1, page);
check("count=0 returns just the total", (await j(await call(TOKEN, "GET", "Users?count=0")))?.Resources?.length === 0);

// ---------- Update ----------
const okta = await call(TOKEN, "PATCH", `Users/${a!.id}`, { schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], Operations: [{ op: "replace", value: { active: false } }] });
check("PATCH without a path (Okta style) deactivates", okta.status === 200 && (await j(okta))?.active === false);
const ban = (await db().execute(sql`select banned from users where id = ${a!.id}`)) as unknown as { banned: boolean }[];
check("the account is suspended", ban[0].banned === true);
const entra = await call(TOKEN, "PATCH", `Users/${a!.id}`, { Operations: [{ op: "Replace", path: "active", value: "True" }] });
check("PATCH with a string boolean (Entra ID style) reactivates", entra.status === 200 && (await j(entra))?.active === true);
const nm = await j(await call(TOKEN, "PATCH", `Users/${a!.id}`, { Operations: [{ op: "replace", path: "name.givenName", value: "Alicia" }, { op: "replace", path: "name.familyName", value: "Ng-Lee" }] }));
check("PATCH name by path", nm?.name?.givenName === "Alicia" && nm.name.familyName === "Ng-Lee" && nm.displayName === "Alicia Ng-Lee", nm);
const mail2 = `alicia.${t}@acme.test`;
const em = await j(await call(TOKEN, "PATCH", `Users/${a!.id}`, { Operations: [{ op: "replace", path: 'emails[type eq "work"].value', value: mail2 }] }));
check("PATCH the email with Entra's path", em?.userName === mail2 && em.emails[0].value === mail2, em);
check("…to another domain → 400", (await call(TOKEN, "PATCH", `Users/${a!.id}`, { Operations: [{ op: "replace", path: "userName", value: `x.${t}@evil.test` }] })).status === 400);
check("…to someone else's address → 409", (await call(TOKEN, "PATCH", `Users/${a!.id}`, { Operations: [{ op: "replace", path: "userName", value: `fred.${t}@acme.test` }] })).status === 409);
check("an unknown operation → 400", (await call(TOKEN, "PATCH", `Users/${a!.id}`, { Operations: [{ op: "frobnicate", path: "active", value: true }] })).status === 400);
check("a bad `active` value → 400", (await call(TOKEN, "PATCH", `Users/${a!.id}`, { Operations: [{ op: "replace", path: "active", value: "maybe" }] })).status === 400);
const put = await j(await call(TOKEN, "PUT", `Users/${a!.id}`, { userName: mail2, externalId: "okta-9", name: { givenName: "Al", familyName: "N" }, active: true }));
check("PUT replaces the fields it's given", put?.name?.givenName === "Al" && put.externalId === "okta-9" && put.active === true, put);

// ---------- Existing accounts ----------
const cl = (path: string, body: unknown, cookie = "") =>
  fetch(`${AUTH}/v1/client/${path}?pk=${pk}`, { method: "POST", headers: { "content-type": "application/json", origin: AUTH, cookie, "x-forwarded-for": `198.51.100.${randomInt(1, 250)}` }, body: JSON.stringify(body) });
const bob = `bob.${t}@acme.test`;
const su = await cl("sign_up", { email: bob, password: "a long enough password" });
const bobId = (await su.json()).user.id as string;
const cookie = su.headers.getSetCookie().map((c) => c.split(";")[0]).join("; ");
const secFetch = () => fetch(`${AUTH}/v1/client/me/security?pk=${pk}`, { headers: { cookie, origin: AUTH, "x-forwarded-for": `198.51.100.${randomInt(1, 250)}` } });
check("the self-signed-up account has a working session", (await secFetch()).status === 200);
check("SCIM can't touch an account it hasn't been introduced to", (await call(TOKEN, "GET", `Users/${bobId}`)).status === 404 && (await call(TOKEN, "DELETE", `Users/${bobId}`)).status === 404);
const adopt = await j(await call(TOKEN, "GET", `Users?filter=${encodeURIComponent(`userName eq "${bob}"`)}`));
check("looking up an existing person at its domain adopts them", adopt?.totalResults === 1 && adopt.Resources[0].id === bobId, adopt);
const pw = (await db().execute(sql`select count(*)::int as n from passwords where user_id = ${bobId}`)) as unknown as { n: number }[];
check("their unverified password is removed (pre-registration takeover guard)", pw[0].n === 0);
check("…and their old sessions are signed out", (await secFetch()).status === 401);

const dave = `dave.${t}@other.test`;
const dsu = await cl("sign_up", { email: dave, password: "a long enough password" });
const daveId = (await dsu.json()).user.id as string;
check("an account at another domain is invisible (read)", (await call(TOKEN, "GET", `Users/${daveId}`)).status === 404);
check("…can't be changed", (await call(TOKEN, "PATCH", `Users/${daveId}`, { Operations: [{ op: "replace", path: "active", value: false }] })).status === 404);
check("…can't be deleted", (await call(TOKEN, "DELETE", `Users/${daveId}`)).status === 404);
const lookup = await j(await call(TOKEN, "GET", `Users?filter=${encodeURIComponent(`userName eq "${dave}"`)}`));
check("…and a lookup for it finds nothing", lookup?.totalResults === 0);
const still = (await db().execute(sql`select banned from users where id = ${daveId}`)) as unknown as { banned: boolean }[];
check("…and it's untouched", still.length === 1 && still[0].banned === false);
check("another connection's token can't reach this connection's users", (await (async () => {
  const t2 = (await (await api("POST", `saml_connections/${other.id}/scim_token`)).json()).token as string;
  return (await call(t2, "GET", `Users/${a!.id}`, undefined, other.id)).status;
})()) === 404);

// ---------- Delete ----------
const del = await call(TOKEN, "DELETE", `Users/${a!.id}`);
check("delete → 204", del.status === 204);
const gone = (await db().execute(sql`select count(*)::int as n from users where id = ${a!.id}`)) as unknown as { n: number }[];
check("…and the account is gone", gone[0].n === 0);
check("deleting again → 404", (await call(TOKEN, "DELETE", `Users/${a!.id}`)).status === 404);

// ---------- Groups -> organization roles ----------
const org2 = `org_scimg${t}`;
await db().execute(sql`insert into organizations (id, instance_id, name, slug) values (${org2}, ${instanceId}, 'Roles Inc', ${`roles-${t}`})`);
const rc = await mk("Roles", "roles.test", org2);
const RT: string = (await (await api("POST", `saml_connections/${rc.id}/scim_token`)).json()).token;
const g = (method: string, path: string, body?: unknown) => call(RT, method, path, body, rc.id);
const mkUser = async (n: string) => {
  const email = `${n}.${t}@roles.test`;
  return (await j(await g("POST", "Users", { userName: email, emails: [{ value: email, primary: true }], active: true })))!.id as string;
};
const [u1, u2, u3, u4] = [await mkUser("g1"), await mkUser("g2"), await mkUser("g3"), await mkUser("g4")];
// A person the connection doesn't manage, who is already an admin of the organization.
const bossEmail = `boss.${t}@elsewhere.test`;
const boss = (await (await fetch(`${AUTH}/v1/client/sign_up?pk=${pk}`, { method: "POST", headers: { "content-type": "application/json", origin: AUTH }, body: JSON.stringify({ email: bossEmail, password: "a long enough password" }) })).json()).user.id as string;
await db().execute(sql`insert into memberships (org_id, user_id, role) values (${org2}, ${boss}, 'admin'), (${org2}, ${u1}, 'member'), (${org2}, ${u2}, 'member'), (${org2}, ${u3}, 'member') on conflict do nothing`);
const roleOf = async (uid: string) => ((await db().execute(sql`select role from memberships where org_id = ${org2} and user_id = ${uid}`)) as unknown as { role: string }[])[0]?.role ?? null;

check("discovery lists the Group resource", (await (await call(TOKEN, "GET", "ResourceTypes")).text()).includes("/Groups"));
const adm = await g("POST", "Groups", { schemas: [SCHEMA_GROUP], displayName: "Admins", externalId: "grp-1", members: [{ value: u1 }] });
const admBody = (await j(adm))!;
check("create a group → 201 with members", adm.status === 201 && /^sg_/.test(admBody?.id) && admBody.displayName === "Admins" && admBody.members?.[0]?.value === u1 && admBody.meta?.resourceType === "Group", admBody);
const GID: string = admBody!.id;
check("with no admin groups configured, roles are left alone", (await roleOf(u1)) === "member");
check("a duplicate name (any case) is a 409", (await g("POST", "Groups", { displayName: "ADMINS" })).status === 409);
check("only people this connection manages can be members", (await g("POST", "Groups", { displayName: "Bad", members: [{ value: boss }] })).status === 400);
check("get one group", (await j(await g("GET", `Groups/${GID}`)))?.displayName === "Admins");
check("filter by displayName", (await j(await g("GET", `Groups?filter=${encodeURIComponent('displayName eq "admins"')}`)))?.totalResults === 1);
check("other filters are refused", (await g("GET", `Groups?filter=${encodeURIComponent('members eq "x"')}`)).status === 400);
check("list", (await j(await g("GET", "Groups")))?.totalResults === 1);
check("another connection's token can't see it", (await call(TOKEN, "GET", `Groups/${GID}`, undefined, rc.id)).status === 401 && (await call(TOKEN, "GET", `Groups/${GID}`)).status === 404);

const cfg = await api("PATCH", `saml_connections/${rc.id}`, { scimAdminGroups: ["  ADMINS "] });
const cfgBody = await cfg.json();
check("set the admin group list (names are stored lowercase)", cfg.status === 200 && cfgBody.scim.adminGroups?.[0] === "admins", cfgBody);
check("…members of that group become admins right away", (await roleOf(u1)) === "admin");
check("…people the connection doesn't manage are untouched", (await roleOf(boss)) === "admin" && (await roleOf(u2)) === "member");

await g("PATCH", `Groups/${GID}`, { Operations: [{ op: "add", path: "members", value: [{ value: u2 }] }] });
check("Okta-style add: u2 becomes admin", (await roleOf(u2)) === "admin");
await g("PATCH", `Groups/${GID}`, { Operations: [{ op: "remove", path: `members[value eq "${u2}"]` }] });
check("Entra-style remove: u2 is a member again", (await roleOf(u2)) === "member");
await g("PATCH", `Groups/${GID}`, { Operations: [{ op: "add", value: { members: [{ value: u4 }] } }] });
check("an admin who isn't in the organization yet is added as admin", (await roleOf(u4)) === "admin");
await g("PATCH", `Groups/${GID}`, { Operations: [{ op: "remove", path: "members", value: [{ value: u4 }] }] });
check("remove with a value list works (u4 demoted)", (await roleOf(u4)) === "member");

const ren = await g("PATCH", `Groups/${GID}`, { Operations: [{ op: "replace", path: "displayName", value: "Staff" }] });
check("renaming the group takes its members out of the admin list", ren.status === 200 && (await roleOf(u1)) === "member");
await g("PATCH", `Groups/${GID}`, { Operations: [{ op: "replace", value: { displayName: "admins" } }] });
check("…and back in again (path-less replace)", (await roleOf(u1)) === "admin");

const putG = await g("PUT", `Groups/${GID}`, { displayName: "Admins", members: [{ value: u3 }] });
check("PUT replaces the members: u3 in, u1 out", putG.status === 200 && (await roleOf(u3)) === "admin" && (await roleOf(u1)) === "member");
check("a user removed from the IdP drops out of its groups", (await g("DELETE", `Users/${u3}`)).status === 204 && ((await j(await g("GET", `Groups/${GID}`)))?.members ?? []).length === 0);

await g("PATCH", `Groups/${GID}`, { Operations: [{ op: "add", path: "members", value: [{ value: u1 }] }] });
await db().execute(sql`delete from memberships where org_id = ${org2} and user_id = ${boss}`);
const delG = await g("DELETE", `Groups/${GID}`);
check("deleting the group → 204", delG.status === 204 && (await g("GET", `Groups/${GID}`)).status === 404);
check("the organization's last admin is never demoted", (await roleOf(u1)) === "admin");

const off2 = await api("PATCH", `saml_connections/${rc.id}`, { scimAdminGroups: [] });
check("an empty list turns role management off", off2.status === 200 && (await roleOf(u1)) === "admin");

// ---------- Rotating and revoking ----------
const rotated = (await (await api("POST", `saml_connections/${conn.id}/scim_token`)).json()).token as string;
check("a new token works", (await call(rotated, "GET", "Users")).status === 200);
check("the old token stops working at once", (await call(TOKEN, "GET", "Users")).status === 401);
const off = await api("DELETE", `saml_connections/${conn.id}/scim_token`);
check("turning provisioning off", off.status === 200 && (await call(rotated, "GET", "Users")).status === 401);
const del2 = await api("DELETE", `saml_connections/${conn.id}`);
check("deleting a connection removes its provisioning", del2.status === 200);

await new Promise((r) => setTimeout(r, 400));
const audit = (await listAudit(instanceId, { limit: 200 })).data;
const has = (type: string) => audit.some((e) => e.type === type);
check("audit log: tokens, creates, deactivate, reactivate, delete", ["scim_token.created", "scim_token.revoked", "scim_user.created", "scim_user.updated", "scim_user.deactivated", "scim_user.reactivated", "scim_user.deleted", "scim_group.created", "scim_group.updated", "scim_group.deleted", "scim_role.changed"].every(has), audit.map((e) => e.type));

await closeDb();
await closeCache();
console.log(failures ? `\n${failures} check(s) failed` : "\nAll SCIM checks passed");
process.exit(failures ? 1 : 0);
