/** Account-management checks: profile, password change, sessions. Needs the service on :3000. */
import { seedInstance } from "./seed";
import { closeDb } from "../src/lib/db";
import { closeCache } from "../src/lib/cache";

const AUTH = "http://localhost:3000";
let failures = 0;
const check = (name: string, ok: boolean, detail?: unknown) => {
  console.log(`${ok ? "✓" : "✗"} ${name}${ok ? "" : ` — ${JSON.stringify(detail)}`}`);
  if (!ok) failures++;
};

const { publishableKey: pk } = await seedInstance("Account E2E", []);

/** A browser with its own cookie jar and user agent. */
class Browser {
  cookies = new Map<string, string>();
  constructor(public ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/537.36 Chrome/130.0 Safari/537.36", public ip = "203.0.113.42") {}
  async call(method: string, path: string, body?: unknown) {
    const res = await fetch(`${AUTH}/v1/client/${path}`, {
      method,
      headers: {
        "content-type": "application/json",
        "x-publishable-key": pk,
        origin: AUTH,
        "user-agent": this.ua,
        "x-forwarded-for": this.ip,
        cookie: [...this.cookies].map(([k, v]) => `${k}=${v}`).join("; "),
      },
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

const email = `acct.${Date.now()}@example.com`;
const laptop = new Browser();
await laptop.post("sign_up", { email, password: "original password", firstName: "Grace" });

// ---------- Profile ----------
const upd = await laptop.call("PATCH", "me", { firstName: "Grace", lastName: "Hopper" });
check("update profile", upd.status === 200 && upd.body.user.lastName === "Hopper", upd.body);
const clr = await laptop.call("PATCH", "me", { lastName: null });
check("clear a profile field with null", clr.body.user.lastName === null && clr.body.user.firstName === "Grace", clr.body);
check("profile update needs a session", (await new Browser().call("PATCH", "me", { firstName: "x" })).status === 401);
check("over-long name rejected", (await laptop.call("PATCH", "me", { firstName: "x".repeat(101) })).status === 422);

// ---------- Security info ----------
const sec = await laptop.get("me/security");
check("security info", sec.body.hasPassword === true && sec.body.twoFactorEnabled === false && Array.isArray(sec.body.connectedAccounts), sec.body);

// ---------- Sessions ----------
const phone = new Browser("Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Version/18.0 Mobile/15E148 Safari/604.1", "198.51.100.7");
const tablet = new Browser("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Gecko/20100101 Firefox/131.0", "2001:db8:85a3::8a2e:370:7334");
await phone.post("sign_in", { email, password: "original password" });
await tablet.post("sign_in", { email, password: "original password" });

const list = (await laptop.get("sessions")).body.sessions as { id: string; current: boolean; device: string; ipHint: string | null }[];
check("lists all 3 active sessions", list.length === 3, list);
check("marks the current session", list.filter((s) => s.current).length === 1 && list.find((s) => s.current)!.device === "Chrome on macOS", list);
check("describes devices", list.some((s) => s.device === "Safari on iOS") && list.some((s) => s.device === "Firefox on Windows"), list.map((s) => s.device));
check("masks IPv4 addresses", list.some((s) => s.ipHint === "198.51.x.x") && !JSON.stringify(list).includes("198.51.100.7"), list.map((s) => s.ipHint));
check("masks IPv6 addresses", list.some((s) => s.ipHint === "2001:db8:85a3:…") && !JSON.stringify(list).includes("370:7334"), list.map((s) => s.ipHint));

const phoneSession = list.find((s) => s.device === "Safari on iOS")!;
const current = list.find((s) => s.current)!;
check("can't revoke the current session via revoke route", (await laptop.post(`sessions/${current.id}/revoke`)).body.error?.code === "current_session");

// Another user must not be able to sign out this user's devices
const stranger = new Browser();
await stranger.post("sign_up", { email: `stranger.${email}`, password: "stranger password" });
check("another user can't revoke your session (404, not 403: no ID probing)", (await stranger.post(`sessions/${phoneSession.id}/revoke`)).status === 404);
check("…and your phone is still signed in", (await phone.post("session/token")).status === 200);

check("revoke another device", (await laptop.post(`sessions/${phoneSession.id}/revoke`)).status === 200);
check("revoked device can no longer get tokens", (await phone.post("session/token")).status === 401);
check("current device unaffected", (await laptop.post("session/token")).status === 200);

const others = await laptop.post("sessions/revoke_others");
check("sign out all others", others.body.signedOut === 1 && (await tablet.post("session/token")).status === 401, others.body);
check("sessions list now only has this device", (await laptop.get("sessions")).body.sessions.length === 1);

// ---------- Password change ----------
const p2 = new Browser();
await p2.post("sign_in", { email, password: "original password" });
check("wrong current password rejected", (await laptop.post("password/change", { currentPassword: "nope nope", newPassword: "brand new password" })).body.error?.code === "invalid_credentials");
check("short new password rejected", (await laptop.post("password/change", { currentPassword: "original password", newPassword: "short" })).body.error?.code === "password_too_short");
check("…and nothing was signed out by the failed attempts", (await p2.post("session/token")).status === 200);
const chg = await laptop.post("password/change", { currentPassword: "original password", newPassword: "brand new password" });
check("password changed, other sessions signed out", chg.status === 200 && chg.body.otherSessionsSignedOut === 1, chg.body);
check("other device lost access", (await p2.post("session/token")).status === 401);
check("this device kept access", (await laptop.post("session/token")).status === 200);
check("old password no longer works", (await new Browser().post("sign_in", { email, password: "original password" })).body.error?.code === "invalid_credentials");
check("new password works", (await new Browser().post("sign_in", { email, password: "brand new password" })).body.status === "complete");

// ---------- Hosted page ----------
const page = await fetch(`${AUTH}/account?pk=${pk}`);
check("account page renders with security headers", page.status === 200 && page.headers.get("x-frame-options") === "DENY");
check("account page with bad key shows an error", (await (await fetch(`${AUTH}/account?pk=pk_test_bad`)).text()).includes("Missing or invalid publishable key"));

await closeDb();
await closeCache();
console.log(failures ? `\n${failures} check(s) failed` : "\nAll account checks passed");
process.exit(failures ? 1 : 0);
