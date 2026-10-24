/** Custom organization roles and permissions, org_permissions claim, has()/protect(), verified-domain enrollment. Needs the service on :3000 started with DNS_TXT_TEST_FILE=/tmp/daywalker-dns-test.json. */
import { writeFileSync } from "node:fs";
import { sql } from "drizzle-orm";
import { decodeJwt } from "jose";
import { seedInstance } from "./seed";
import { db, closeDb } from "../src/lib/db";
import { cache, closeCache } from "../src/lib/cache";
import { blindIndex } from "../src/lib/crypto";
import { createBackendClient, has, protect, ForbiddenError, verifyToken } from "../packages/sdk/src/server";

const AUTH = "http://localhost:3000";
const DNS_FILE = process.env.DNS_TXT_TEST_FILE ?? "/tmp/daywalker-dns-test.json";
let failures = 0;
const check = (name: string, ok: boolean, detail?: unknown) => {
  console.log(`${ok ? "✓" : "✗"} ${name}${ok ? "" : ` — ${JSON.stringify(detail)?.slice(0, 500)}`}`);
  if (!ok) failures++;
};
const settle = () => new Promise((r) => setTimeout(r, 600));
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const rows = async (q: ReturnType<typeof sql>) => (await db().execute(q)) as unknown as Record<string, any>[];
const dns = (m: Record<string, string[]>) => writeFileSync(DNS_FILE, JSON.stringify(m));
dns({});

const { instanceId, publishableKey: pk, secretKey: sk } = await seedInstance("Roles E2E", []);
const other = await seedInstance("Roles E2E (other)", []);
const api = createBackendClient({ secretKey: sk, apiUrl: AUTH });
const otherApi = createBackendClient({ secretKey: other.secretKey, apiUrl: AUTH });
const err = async (p: Promise<unknown>) => p.then(() => null, (e: { status: number; code: string }) => e);

class Browser {
  cookies = new Map<string, string>();
  constructor(public key = pk, public ip = `198.51.100.${Math.floor(Math.random() * 250) + 1}`) {}
  async call(method: string, path: string, body?: unknown) {
    const res = await fetch(`${AUTH}/v1/client/${path}`, {
      method,
      headers: { "content-type": "application/json", "x-publishable-key": this.key, origin: AUTH, "x-forwarded-for": this.ip, cookie: [...this.cookies].map(([k, v]) => `${k}=${v}`).join("; ") },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    for (const c of res.headers.getSetCookie()) {
      const kv = c.split(";")[0];
      const k = kv.slice(0, kv.indexOf("=")), v = kv.slice(kv.indexOf("=") + 1);
      if (/max-age=0/i.test(c) || !v) this.cookies.delete(k);
      else this.cookies.set(k, v);
    }
    return { status: res.status, body: await res.json().catch(() => null) };
  }
  post = (p: string, b?: unknown) => this.call("POST", p, b);
  get = (p: string) => this.call("GET", p);
  patch = (p: string, b?: unknown) => this.call("PATCH", p, b);
  del = (p: string) => this.call("DELETE", p);
}
const mail = async (to: string) => (await cache().get(`devmail:${blindIndex(to, "devmail")}`)) ?? "";
const code6 = async (to: string) => (await mail(to)).match(/\b(\d{6})\b/)?.[1] ?? "";
async function signUp(b: Browser, email: string, verify = true) {
  const r = await b.post("sign_up", { email, password: "a good password" });
  if (verify) {
    await b.post("email/send_code");
    await b.post("email/verify", { code: await code6(email) });
  }
  return r.body.user.id as string;
}
const claimsOf = async (b: Browser, orgId: string | null) => {
  await b.post("session/active_org", { orgId });
  const t = await b.post("session/token");
  return { jwt: t.body.jwt as string, c: decodeJwt(t.body.jwt) as Record<string, unknown> };
};

// ---------- Roles: definition ----------
const t = Date.now();
const billing = await api.organizationRoles.create({ key: "billing_manager", name: "Billing manager", permissions: ["org:read", "org:billing:manage"] });
check("create a custom role", billing.key === "billing_manager" && !billing.builtIn && billing.permissions.includes("org:billing:manage"), billing);
check("built-in key refused", (await err(api.organizationRoles.create({ key: "admin", name: "x", permissions: [] })))?.status === 409);
check("bad permission string refused (422)", (await err(api.organizationRoles.create({ key: "bad_one", name: "x", permissions: ["Not Valid"] })))?.status === 422);
check("bad key refused (422)", (await err(api.organizationRoles.create({ key: "Bad Key", name: "x", permissions: [] })))?.status === 422);
check("duplicate key refused", (await err(api.organizationRoles.create({ key: "billing_manager", name: "x", permissions: [] })))?.status === 409);
await api.organizationRoles.create({ key: "lead", name: "Team lead", permissions: ["org:read", "members:read", "members:manage", "invitations:manage"] });
const list = await api.organizationRoles.list();
check("list: built-ins first, admin holds every custom permission", list[0].key === "admin" && list[1].key === "member" && list[0].permissions.includes("org:billing:manage"), list);
check("roles are per instance", (await otherApi.organizationRoles.list()).length === 2);
check("secret key required", (await fetch(`${AUTH}/v1/organization_roles`, { headers: { authorization: `Bearer ${pk}` } })).status === 401);

// ---------- Members, claims ----------
const alice = new Browser(), bob = new Browser(), carol = new Browser(), dave = new Browser();
const aEmail = `alice.${t}@example.com`;
const aliceId = await signUp(alice, aEmail);
const bobId = await signUp(bob, `bob.${t}@example.com`);
const carolId = await signUp(carol, `carol.${t}@example.com`);
const daveId = await signUp(dave, `dave.${t}@example.com`);
const org = (await alice.post("organizations", { name: "Acme" })).body.organization;
const orgId = org.id as string;
check("creator is admin, organizations list carries permissions", (await alice.get("organizations")).body.organizations[0].permissions.includes("org:billing:manage"));
for (const [u, r] of [[bobId, "member"], [carolId, "member"], [daveId, "member"]]) await db().execute(sql`insert into memberships (org_id, user_id, role) values (${orgId}, ${u}, ${r})`);
check("frontend lists roles", (await bob.get("organization_roles")).body.roles.length === 4);

const ch = await alice.patch(`organizations/${orgId}/members/${bobId}`, { role: "billing_manager" });
check("admin assigns a custom role", ch.status === 200 && ch.body.role === "billing_manager", ch.body);
check("unknown role refused", (await alice.patch(`organizations/${orgId}/members/${bobId}`, { role: "nope" })).body.error?.code === "unknown_role");
const bc = await claimsOf(bob, orgId);
check("JWT carries org_role and org_permissions", bc.c.org_role === "billing_manager" && JSON.stringify(bc.c.org_permissions) === JSON.stringify(["org:read", "org:billing:manage"]), bc.c);
const ac = await claimsOf(alice, orgId);
check("admin token has system + custom permissions", (ac.c.org_permissions as string[]).includes("org:manage") && (ac.c.org_permissions as string[]).includes("org:billing:manage"));
const personal = await claimsOf(alice, null);
check("no org claims without an active org", personal.c.org_permissions === undefined && personal.c.org_id === undefined);

// SDK helpers on a really verified token
const vc = await verifyToken(bc.jwt, { publishableKey: pk, frontendApi: AUTH });
check("verifyToken exposes orgRole + orgPermissions", vc?.orgRole === "billing_manager" && !!vc.orgPermissions?.includes("org:billing:manage"), vc);
check("has() by permission / role", has(vc, { permission: "org:billing:manage" }) && has(vc, { role: "billing_manager" }) && !has(vc, { permission: "org:manage" }) && !has(vc, { role: "admin" }));
check("has() needs every key; empty check and no org are false", !has(vc, { permission: "org:billing:manage", role: "admin" }) && !has(vc, {}) && !has(null, { permission: "x:y" }));
let threw: unknown = null;
try { protect(vc, { permission: "org:manage" }); } catch (e) { threw = e; }
check("protect() throws ForbiddenError (403)", threw instanceof ForbiddenError && (threw as ForbiddenError).status === 403);
check("protect() passes when allowed", (() => { try { protect(vc, { permission: "org:read" }); return true; } catch { return false; } })());

// ---------- Permission enforcement and escalation ----------
check("custom role without members:manage can't change roles", (await bob.patch(`organizations/${orgId}/members/${carolId}`, { role: "member" })).status === 403);
check("…or invite", (await bob.post(`organizations/${orgId}/invitations`, { email: `x.${t}@example.com` })).status === 403);
await alice.patch(`organizations/${orgId}/members/${carolId}`, { role: "lead" });
check("lead can read members", (await carol.get(`organizations/${orgId}/members`)).status === 200);
const esc1 = await carol.patch(`organizations/${orgId}/members/${daveId}`, { role: "admin" });
check("lead can't make someone admin (role_exceeds_yours)", esc1.status === 403 && esc1.body.error?.code === "role_exceeds_yours", esc1.body);
const esc2 = await carol.patch(`organizations/${orgId}/members/${daveId}`, { role: "billing_manager" });
check("lead can't hand out a permission it lacks", esc2.status === 403 && esc2.body.error?.code === "role_exceeds_yours", esc2.body);
check("lead can't change an admin", (await carol.patch(`organizations/${orgId}/members/${aliceId}`, { role: "member" })).status === 403);
check("lead can't remove an admin", (await carol.del(`organizations/${orgId}/members/${aliceId}`)).status === 403);
check("lead can't promote itself", (await carol.patch(`organizations/${orgId}/members/${carolId}`, { role: "admin" })).status === 403);
check("lead can assign roles it covers", (await carol.patch(`organizations/${orgId}/members/${daveId}`, { role: "lead" })).status === 200);
const esc3 = await carol.post(`organizations/${orgId}/invitations`, { email: `inv.${t}@example.com`, role: "admin" });
check("lead can't invite as admin", esc3.status === 403, esc3.body);
check("lead can invite a covered role", (await carol.post(`organizations/${orgId}/invitations`, { email: `inv.${t}@example.com`, role: "member" })).status === 201);

// Role edits apply to new tokens; deleting is guarded
await api.organizationRoles.update("billing_manager", { permissions: ["org:read", "org:billing:read"] });
const bc2 = await claimsOf(bob, orgId);
check("editing a role changes the next token", JSON.stringify(bc2.c.org_permissions) === JSON.stringify(["org:read", "org:billing:read"]), bc2.c);
check("admin's list follows (old custom permission gone)", !(await api.organizationRoles.list())[0].permissions.includes("org:billing:manage"));
check("deleting a role in use → role_in_use", (await err(api.organizationRoles.delete("billing_manager")))?.code === "role_in_use");
const setRole = await fetch(`${AUTH}/v1/organizations/${orgId}/members/${bobId}`, { method: "PATCH", headers: { authorization: `Bearer ${sk}`, "content-type": "application/json" }, body: JSON.stringify({ role: "member" }) });
check("backend sets a member's role", setRole.status === 200);
check("last admin can't be demoted via backend", (await fetch(`${AUTH}/v1/organizations/${orgId}/members/${aliceId}`, { method: "PATCH", headers: { authorization: `Bearer ${sk}`, "content-type": "application/json" }, body: JSON.stringify({ role: "member" }) })).status === 400);
await db().execute(sql`delete from invitations where org_id = ${orgId}`);
await api.organizationRoles.create({ key: "temp_role", name: "Temp", permissions: [] });
check("delete an unused role", (await api.organizationRoles.delete("temp_role")).deleted === true);
check("deleted role is gone", (await err(api.organizationRoles.get?.("temp_role") ?? Promise.reject({ status: 404 })))?.status === 404);
check("a member whose role vanished has no permissions", await (async () => {
  await db().execute(sql`update memberships set role = 'ghost' where org_id = ${orgId} and user_id = ${bobId}`);
  await cache().del(`mem:${orgId}:${bobId}`);
  return (await bob.get(`organizations/${orgId}/members`)).status === 403;
})());
await db().execute(sql`update memberships set role = 'member' where org_id = ${orgId} and user_id = ${bobId}`);
await cache().del(`mem:${orgId}:${bobId}`);
check("audit log has role events", await (async () => { await settle(); const a = await api.auditEvents.list({ type: "org_role.created" }); return a.data.length >= 2; })());

// ---------- Domains ----------
const domain = `acme-${t}.example.org`;
const addNo = await bob.post(`organizations/${orgId}/domains`, { domain });
check("non-admin can't add a domain", addNo.status === 403, addNo.body);
check("free-mail domains refused", (await alice.post(`organizations/${orgId}/domains`, { domain: "gmail.com" })).body.error?.code === "domain_not_allowed");
check("invalid domain refused", (await alice.post(`organizations/${orgId}/domains`, { domain: "not a domain" })).body.error?.code === "invalid_domain");
const added = (await alice.post(`organizations/${orgId}/domains`, { domain: domain.toUpperCase() })).body.domain;
check("add a domain: lowercased, unverified, DNS instructions", added.domain === domain && !added.verified && added.dns.name === `_daywalker.${domain}` && added.dns.value.startsWith("daywalker-verify="), added);
check("enrollment refused before verification", (await alice.patch(`organizations/${orgId}/domains/${added.id}`, { enrollment: "suggest" })).body.error?.code === "domain_unverified");
check("DNS check fails with no record", (await alice.post(`organizations/${orgId}/domains/${added.id}/verify`, { method: "dns" })).body.error?.code === "verification_failed");
dns({ [`_daywalker.${domain}`]: ["daywalker-verify=wrong"] });
check("…and with the wrong value", (await alice.post(`organizations/${orgId}/domains/${added.id}/verify`, { method: "dns" })).body.error?.code === "verification_failed");
dns({ [`_daywalker.${domain}`]: [added.dns.value] });
const ver = await alice.post(`organizations/${orgId}/domains/${added.id}/verify`, { method: "dns" });
check("DNS TXT verifies the domain", ver.status === 200 && ver.body.domain.verified && ver.body.domain.verifiedVia === "dns", ver.body);

// Another organization in the same instance can't take it
const org2 = (await bob.post("organizations", { name: "Rival" })).body.organization.id as string;
check("a verified domain can't be claimed by another organization", (await bob.post(`organizations/${org2}/domains`, { domain })).body.error?.code === "domain_taken");
// but may add one that's only unverified elsewhere, and verification races lose
const d2 = `second-${t}.example.org`;
const a2 = (await alice.post(`organizations/${orgId}/domains`, { domain: d2 })).body.domain;
const b2 = (await bob.post(`organizations/${org2}/domains`, { domain: d2 })).body.domain;
dns({ [`_daywalker.${domain}`]: [added.dns.value], [`_daywalker.${d2}`]: [a2.dns.value, b2.dns.value] });
check("first to verify wins", (await alice.post(`organizations/${orgId}/domains/${a2.id}/verify`, { method: "dns" })).status === 200);
check("second gets domain_taken", (await bob.post(`organizations/${org2}/domains/${b2.id}/verify`, { method: "dns" })).body.error?.code === "domain_taken");

// Email verification
const d3 = `mailverify-${t}.example.org`;
const a3 = (await alice.post(`organizations/${orgId}/domains`, { domain: d3 })).body.domain;
check("only role mailboxes accepted (422)", (await alice.post(`organizations/${orgId}/domains/${a3.id}/verify`, { method: "email", mailbox: "ceo" })).status === 422);
const sent = await alice.post(`organizations/${orgId}/domains/${a3.id}/verify`, { method: "email", mailbox: "postmaster" });
check("code goes to postmaster@domain", sent.body.sentTo === `postmaster@${d3}`, sent.body);
const dcode = await code6(`postmaster@${d3}`);
check("wrong code refused", (await alice.post(`organizations/${orgId}/domains/${a3.id}/verify`, { method: "email", code: dcode === "000000" ? "111111" : "000000" })).body.error?.code === "invalid_code");
const ev = await alice.post(`organizations/${orgId}/domains/${a3.id}/verify`, { method: "email", code: dcode });
check("email code verifies the domain", ev.status === 200 && ev.body.domain.verifiedVia === "email", ev.body);
check("domain list for admins only", (await bob.get(`organizations/${orgId}/domains`)).status === 403 && (await alice.get(`organizations/${orgId}/domains`)).body.domains.length === 3);

// ---------- Enrollment: suggest ----------
check("unsafe role for domain joins refused (admin)", (await alice.patch(`organizations/${orgId}/domains/${added.id}`, { enrollment: "suggest", role: "admin" })).body.error?.code === "role_not_allowed");
check("…and a role that manages members", (await alice.patch(`organizations/${orgId}/domains/${added.id}`, { enrollment: "suggest", role: "lead" })).body.error?.code === "role_not_allowed");
const set = await alice.patch(`organizations/${orgId}/domains/${added.id}`, { enrollment: "suggest", role: "billing_manager" });
check("set suggest with a safe custom role", set.status === 200 && set.body.domain.enrollment === "suggest", set.body);
check("role that's used for domain joins can't gain managing permissions", (await err(api.organizationRoles.update("billing_manager", { permissions: ["members:manage"] })))?.code === "role_in_use");
check("…nor be deleted", (await err(api.organizationRoles.delete("billing_manager")))?.code === "role_in_use");

const mk = async (local: string, host = domain, verify = true) => { const b = new Browser(); const email = `${local}.${t}@${host}`; const id = await signUp(b, email, verify); return { b, id, email }; };
const sg = await mk("sue");
const unv = await mk("ursula", domain, false);
const sub = await mk("sam", `team.${domain}`);
const oth = await mk("olga", `elsewhere-${t}.example.org`);
const sgs = (await sg.b.get("organizations/suggestions")).body.suggestions;
check("verified email at the domain is offered the organization", sgs.length === 1 && sgs[0].id === orgId && sgs[0].domain === domain, sgs);
check("unverified email: nothing offered", (await unv.b.get("organizations/suggestions")).body.suggestions.length === 0);
check("subdomain: nothing offered", (await sub.b.get("organizations/suggestions")).body.suggestions.length === 0);
check("other domain: nothing offered", (await oth.b.get("organizations/suggestions")).body.suggestions.length === 0);
check("unverified can't accept (404, same as no suggestion)", (await unv.b.post(`organizations/suggestions/${orgId}/accept`, {})).status === 404);
check("other domain can't accept", (await oth.b.post(`organizations/suggestions/${orgId}/accept`, {})).status === 404);
const acc = await sg.b.post(`organizations/suggestions/${orgId}/accept`, {});
check("accepting joins with the domain's role", acc.status === 200 && acc.body.organization.role === "billing_manager", acc.body);
check("no longer suggested once a member", (await sg.b.get("organizations/suggestions")).body.suggestions.length === 0);
check("suggest mode does NOT auto-join others", (await rows(sql`select count(*)::int c from memberships where org_id = ${orgId} and user_id in (${unv.id}, ${sub.id}, ${oth.id})`))[0].c === 0);

// ---------- Enrollment: auto join ----------
const pre = await mk("pat"); // verified before auto-join is switched on
await alice.patch(`organizations/${orgId}/domains/${added.id}`, { enrollment: "auto_join" });
await cache().del(`orgdom:${instanceId}`);
const fresh = await mk("fay"); // verifies email after: joins at verification
await settle();
check("verifying an email joins automatically", (await rows(sql`select role from memberships where org_id = ${orgId} and user_id = ${fresh.id}`))[0]?.role === "billing_manager");
check("not before sign-in for someone verified earlier", (await rows(sql`select count(*)::int c from memberships where org_id = ${orgId} and user_id = ${pre.id}`))[0].c === 0);
const re = new Browser();
await re.post("sign_in", { email: pre.email, password: "a good password" });
await settle();
check("signing in joins them", (await rows(sql`select role from memberships where org_id = ${orgId} and user_id = ${pre.id}`))[0]?.role === "billing_manager");
check("unverified / subdomain / other domain still not joined", (await rows(sql`select count(*)::int c from memberships where org_id = ${orgId} and user_id in (${unv.id}, ${sub.id}, ${oth.id})`))[0].c === 0);
const unv2 = new Browser();
await unv2.post("sign_in", { email: unv.email, password: "a good password" });
await settle();
check("an unverified address never joins, even on sign-in", (await rows(sql`select count(*)::int c from memberships where org_id = ${orgId} and user_id = ${unv.id}`))[0].c === 0);
check("membership events + audit", await (async () => { const a = await api.auditEvents.list({ type: "org_domain.joined" }); return a.data.length >= 3; })());

// Membership limit is respected
await db().execute(sql`update instances set settings = settings || '{"organizations":{"membershipLimit":1}}'::jsonb where id = ${instanceId}`);
await cache().del(`ins:${instanceId}`);
const full = await mk("gus");
await settle();
check("a full organization isn't joined", (await rows(sql`select count(*)::int c from memberships where org_id = ${orgId} and user_id = ${full.id}`))[0].c === 0);
await db().execute(sql`update instances set settings = settings - 'organizations' where id = ${instanceId}`);
await cache().del(`ins:${instanceId}`);

// ---------- Removal, isolation ----------
check("removing a domain", (await alice.del(`organizations/${orgId}/domains/${added.id}`)).status === 200);
await cache().del(`orgdom:${instanceId}`);
const late = await mk("lea");
await settle();
check("after removal nobody joins; earlier joiners stay", (await rows(sql`select count(*)::int c from memberships where org_id = ${orgId} and user_id = ${late.id}`))[0].c === 0 && (await rows(sql`select count(*)::int c from memberships where org_id = ${orgId} and user_id = ${fresh.id}`))[0].c === 1);
check("backend lists domains", (await api.organizationDomains.list(orgId)).length === 2);
check("other instance can't see them", (await err(otherApi.organizationDomains.list(orgId)))?.status === 404);
const bdom = await api.organizationDomains.add(orgId, `viaapi-${t}.example.org`);
check("backend adds a domain", !bdom.verified && !!bdom.dns);
check("backend removes it", (await api.organizationDomains.remove(orgId, bdom.id)).deleted === true);

await closeCache();
await closeDb();
console.log(failures ? `\n${failures} check(s) failed` : "\nAll organization role and domain checks passed");
process.exit(failures ? 1 : 0);
