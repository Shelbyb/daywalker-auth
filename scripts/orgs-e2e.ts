/** Organization checks: roles, invitations, active org claims, tenant isolation. Needs the service on :3000. */
import { seedInstance } from "./seed";
import { closeDb } from "../src/lib/db";
import { cache, closeCache } from "../src/lib/cache";
import { blindIndex } from "../src/lib/crypto";
import { decodeJwt } from "jose";

const AUTH = "http://localhost:3000";
let failures = 0;
const check = (name: string, ok: boolean, detail?: unknown) => {
  console.log(`${ok ? "✓" : "✗"} ${name}${ok ? "" : ` — ${JSON.stringify(detail)}`}`);
  if (!ok) failures++;
};
const { publishableKey: pk, secretKey: sk } = await seedInstance("Orgs E2E", []);
const other = await seedInstance("Orgs E2E (other tenant)", []);

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
    return { status: res.status, body: await res.json() };
  }
  post = (p: string, b?: unknown) => this.call("POST", p, b);
  get = (p: string) => this.call("GET", p);
}
const mail = async (to: string) => (await cache().get(`devmail:${blindIndex(to, "devmail")}`)) ?? "";
async function signUp(b: Browser, email: string, verify = true) {
  const r = await b.post("sign_up", { email, password: "a good password" });
  if (verify) {
    await b.post("email/send_code");
    await b.post("email/verify", { code: (await mail(email)).match(/\b(\d{6})\b/)![1] });
  }
  return r.body.user.id as string;
}

const t = Date.now();
const aEmail = `owner.${t}@example.com`, bEmail = `bob.${t}@example.com`, cEmail = `eve.${t}@example.com`;
const alice = new Browser(), bob = new Browser(), eve = new Browser();
const aliceId = await signUp(alice, aEmail);
const bobId = await signUp(bob, bEmail);
await signUp(eve, cEmail);

// ---------- Create / list ----------
check("orgs need a session", (await new Browser().get("organizations")).status === 401);
const created = await alice.post("organizations", { name: "Acme Inc" });
const orgId = created.body.organization?.id;
check("create org → creator is admin", created.status === 201 && created.body.organization.role === "admin", created.body);
check("empty name rejected", (await alice.post("organizations", { name: "  " })).status === 422);
check("list shows my org", (await alice.get("organizations")).body.organizations.some((o: { id: string }) => o.id === orgId));
check("non-members get 404 (org existence not leaked)", (await bob.get(`organizations/${orgId}/members`)).status === 404);

// ---------- Invitations ----------
check("non-admin can't invite", (await bob.post(`organizations/${orgId}/invitations`, { email: bEmail })).status === 404);
const inv = await alice.post(`organizations/${orgId}/invitations`, { email: bEmail, role: "member" });
check("admin can invite", inv.status === 201, inv.body);
const link = (await mail(bEmail)).match(/token=([^\s&]+)/)?.[1];
const token = link ? decodeURIComponent(link) : "";
check("invite email contains a link with a token", token.length > 20);
check("preview works signed-out", (await new Browser().post("invitations/preview", { token })).body.orgName === "Acme Inc");
check("bad token preview → 400", (await new Browser().post("invitations/preview", { token: "x".repeat(40) })).status === 400);
check("wrong user can't accept (email mismatch)", (await eve.post("invitations/accept", { token })).status >= 400);
const acc = await bob.post("invitations/accept", { token });
check("invitee accepts → member", acc.status === 200 && acc.body.organization.role === "member", acc.body);
check("token is single use", (await bob.post("invitations/accept", { token })).status >= 400);
const members = await alice.get(`organizations/${orgId}/members`);
check("members list has both", members.body.members?.length === 2, members.body);

// ---------- Roles ----------
check("member can't change roles", (await bob.call("PATCH", `organizations/${orgId}/members/${aliceId}`, { role: "member" })).status === 403);
check("last admin can't be demoted", (await alice.call("PATCH", `organizations/${orgId}/members/${aliceId}`, { role: "member" })).status >= 400);
check("promote bob", (await alice.call("PATCH", `organizations/${orgId}/members/${bobId}`, { role: "admin" })).status === 200);
check("now alice can step down", (await alice.call("PATCH", `organizations/${orgId}/members/${aliceId}`, { role: "member" })).status === 200);
check("member can't rename", (await alice.call("PATCH", `organizations/${orgId}`, { name: "Nope" })).status === 403);
check("admin can rename", (await bob.call("PATCH", `organizations/${orgId}`, { name: "Acme Corp" })).status === 200);

// ---------- Active org + JWT claims ----------
const sw = await alice.post("session/active_org", { orgId });
const claims = decodeJwt(sw.body.jwt);
check("active org puts org_id/org_role in the JWT", claims.org_id === orgId && claims.org_role === "member", claims);
check("can't activate an org you're not in", (await eve.post("session/active_org", { orgId })).status >= 400);
check("personal mode drops the claims", decodeJwt((await alice.post("session/active_org", { orgId: null })).body.jwt).org_id === undefined);

// ---------- Leaving / removing ----------
check("last admin can't leave", (await bob.call("DELETE", `organizations/${orgId}/members/me`)).status >= 400);
check("admin removes a member", (await bob.call("DELETE", `organizations/${orgId}/members/${aliceId}`)).status === 200);
check("removed member loses access", (await alice.get(`organizations/${orgId}/members`)).status === 404);

// ---------- Tenant isolation + backend API ----------
const foreign = new Browser(other.publishableKey);
await signUp(foreign, `x.${t}@example.com`);
check("other tenant can't see the org", (await foreign.get(`organizations/${orgId}/members`)).status === 404);
const be = await fetch(`${AUTH}/v1/organizations`, { headers: { authorization: `Bearer ${sk}` } });
check("backend API lists orgs", (await be.json()).data.some((o: { id: string }) => o.id === orgId));
const beOther = await fetch(`${AUTH}/v1/organizations`, { headers: { authorization: `Bearer ${other.secretKey}` } });
check("backend API is tenant-scoped", !(await beOther.json()).data.some((o: { id: string }) => o.id === orgId));
const bm = await fetch(`${AUTH}/v1/organizations/${orgId}/members`, { headers: { authorization: `Bearer ${sk}` } });
check("backend members endpoint", (await bm.json()).data.length === 1);
check("hosted accept-invite page renders", (await fetch(`${AUTH}/accept-invite?pk=${pk}&token=abc`)).status === 200);

// ---------- Delete ----------
check("member can't delete org", (await alice.call("DELETE", `organizations/${orgId}`)).status === 404);
check("admin deletes org", (await bob.call("DELETE", `organizations/${orgId}`)).status === 200);
check("org is gone", (await bob.get("organizations")).body.organizations.length === 0);

await closeDb();
await closeCache();
console.log(failures ? `\n${failures} check(s) failed` : "\nAll organization checks passed");
process.exit(failures ? 1 : 0);
