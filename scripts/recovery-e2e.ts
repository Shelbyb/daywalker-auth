/** Email verification + password reset checks. Needs the service on :3000 with MAIL_TRANSPORT=dev. */
import { seedInstance } from "./seed";
import { cache, closeCache } from "../src/lib/cache";
import { blindIndex } from "../src/lib/crypto";
import { closeDb } from "../src/lib/db";

const BASE = "http://localhost:3000";
let failures = 0;
const check = (name: string, ok: boolean, detail?: unknown) => {
  console.log(`${ok ? "✓" : "✗"} ${name}${ok ? "" : ` — ${JSON.stringify(detail)}`}`);
  if (!ok) failures++;
};

const { publishableKey: pk } = await seedInstance("Recovery E2E", []);
const email = `lin.${Date.now()}@example.com`;
const devCode = async (to: string) => (await cache().get(`devmail:${blindIndex(to, "devmail")}`))?.match(/\b(\d{6})\b/)?.[1] ?? null;
const clearMail = (to: string) => cache().del(`devmail:${blindIndex(to, "devmail")}`);

function jar() {
  let cookie = "";
  return async (path: string, body?: unknown) => {
    const res = await fetch(`${BASE}/v1/client/${path}`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-publishable-key": pk, origin: BASE, ...(cookie ? { cookie } : {}) },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const sc = res.headers.get("set-cookie");
    if (sc) cookie = sc.split(";")[0];
    return { status: res.status, body: await res.json() };
  };
}

// ----- Email verification -----
const a = jar();
const su = await a("sign_up", { email, password: "first password!" });
check("new accounts start unverified", su.body.user.emailAddresses[0].verified === false);
check("send code (signed in) → 200", (await a("email/send_code")).status === 200);
const code1 = await devCode(email);
check("code was emailed", !!code1 && /^\d{6}$/.test(code1));
const wrong = String((Number(code1) + 1) % 1_000_000).padStart(6, "0");
check("wrong code → invalid_code", (await a("email/verify", { code: wrong })).body.error?.code === "invalid_code");
const ok = await a("email/verify", { code: code1 });
check("right code verifies the email", ok.status === 200 && ok.body.user.emailAddresses[0].verified === true, ok.body);
check("re-sending after verification → already_verified", (await a("email/send_code")).body.error?.code === "already_verified");
check("send code without a session → 401", (await jar()("email/send_code")).status === 401);

// ----- Brute force: a code burns after 5 wrong guesses -----
const email2 = `bf.${Date.now()}@example.com`;
const b = jar();
await b("sign_up", { email: email2, password: "first password!" });
await b("email/send_code");
const code2 = (await devCode(email2))!;
const bad = String((Number(code2) + 1) % 1_000_000).padStart(6, "0");
for (let i = 0; i < 5; i++) await b("email/verify", { code: bad });
check("correct code rejected after 5 wrong guesses", (await b("email/verify", { code: code2 })).body.error?.code === "invalid_code");

// ----- Password reset -----
const anon = jar();
await clearMail("ghost@example.com");
const ghost = await anon("password/forgot", { email: "ghost@example.com" });
const real = await anon("password/forgot", { email });
check("forgot-password responds identically for unknown and real emails", ghost.status === real.status && JSON.stringify(ghost.body) === JSON.stringify(real.body));
check("no email is sent for unknown accounts", (await devCode("ghost@example.com")) === null);
const resetCode = (await devCode(email))!;
check("reset code emailed to the real account", !!resetCode);
check("reset with wrong code → invalid_code", (await anon("password/reset", { email, code: String((Number(resetCode) + 1) % 1e6).padStart(6, "0"), password: "second password!" })).body.error?.code === "invalid_code");
check("reset with short password → rejected before the code is spent", (await anon("password/reset", { email, code: resetCode, password: "x" })).body.error?.code === "password_too_short");
const r = await anon("password/reset", { email, code: resetCode, password: "second password!" });
check("reset with right code → 200", r.status === 200, r.body);
check("existing sessions are revoked by a reset", (await a("session/token")).status === 401);
check("old password no longer works", (await jar()("sign_in", { email, password: "first password!" })).body.error?.code === "invalid_credentials");
check("new password works", (await jar()("sign_in", { email, password: "second password!" })).status === 200);
check("reset code can't be reused", (await anon("password/reset", { email, code: resetCode, password: "third password!" })).body.error?.code === "invalid_code");

await closeDb();
await closeCache();
console.log(failures ? `\n${failures} check(s) failed` : "\nAll recovery checks passed");
process.exit(failures ? 1 : 0);
