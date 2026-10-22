/** Custom email templates: validation, escaping, delivery, reset, branding, isolation. Needs the service on :3000 (MAIL_TRANSPORT=dev). */
import { sql } from "drizzle-orm";
import { seedInstance } from "./seed";
import { cache, closeCache } from "../src/lib/cache";
import { blindIndex } from "../src/lib/crypto";
import { db, closeDb } from "../src/lib/db";
import { getInstance, invalidateInstance } from "../src/lib/auth/instance";
import { composeEmail, renderTemplate, SPECS } from "../src/lib/email-templates";
import { saveTemplateFor, sendTestEmail } from "../src/lib/dashboard";
import { listAudit } from "../src/lib/audit";
import { createBackendClient, BackendError } from "../packages/sdk/src/server";

const BASE = "http://localhost:3000";
let failures = 0;
const check = (name: string, ok: boolean, detail?: unknown) => {
  console.log(`${ok ? "✓" : "✗"} ${name}${ok ? "" : ` — ${JSON.stringify(detail)?.slice(0, 300)}`}`);
  if (!ok) failures++;
};
const settle = () => new Promise((r) => setTimeout(r, 400));
const seed = await seedInstance("Templates E2E", []);
const other = await seedInstance("Templates E2E (other)", []);
const api = createBackendClient({ secretKey: seed.secretKey, apiUrl: BASE });
const otherApi = createBackendClient({ secretKey: other.secretKey, apiUrl: BASE });
const mail = async (to: string) => (await cache().get(`devmail:${blindIndex(to, "devmail")}`)) ?? "";
const fails = async (p: Promise<unknown>, code: string) => {
  try {
    await p;
    return false;
  } catch (e) {
    return e instanceof BackendError && (e.code === code || String(e.status) === code);
  }
};
function jar(pk = seed.publishableKey) {
  let cookie = "";
  return async (path: string, body?: unknown) => {
    const res = await fetch(`${BASE}/v1/client/${path}`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-publishable-key": pk, origin: BASE, "x-forwarded-for": `198.18.0.${Math.floor(Math.random() * 250) + 1}`, ...(cookie ? { cookie } : {}) },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    for (const c of res.headers.getSetCookie()) if (c.startsWith("__dw_rt")) cookie = c.split(";")[0];
    return { status: res.status, body: await res.json().catch(() => null) };
  };
}

// ---------- Defaults ----------
const list = await api.emailTemplates.list();
check("lists all four emails, all on the default wording", list.data.length === 4 && list.data.every((t) => !t.custom) && list.accentColor === null);
check("each lists its placeholders and required ones", list.data.find((t) => t.kind === "sign_in")?.required?.join() === "code,link");

// ---------- Validation ----------
check("unknown placeholder → 400", await fails(api.emailTemplates.update("verify_email", { subject: "Hi", body: "Code {{code}} for {{password}}" }), "invalid_template"));
check("missing a required placeholder → 400", await fails(api.emailTemplates.update("verify_email", { subject: "Hi", body: "No code here" }), "invalid_template"));
check("sign-in email must keep both code and link", await fails(api.emailTemplates.update("sign_in", { subject: "Hi", body: "Code: {{code}}" }), "invalid_template"));
check("multi-line subject (header injection) → 400", await fails(api.emailTemplates.update("verify_email", { subject: "Hi\r\nBcc: victim@example.com", body: "{{code}}" }), "invalid_template"));
check("oversized body → 422", await fails(api.emailTemplates.update("verify_email", { subject: "Hi", body: "{{code}}" + "x".repeat(6000) }), "422"));
check("unknown email kind → 404", (await fetch(`${BASE}/v1/email_templates/password_hint`, { headers: { authorization: `Bearer ${seed.secretKey}` } })).status === 404);
check("needs a secret key (publishable → 401)", (await fetch(`${BASE}/v1/email_templates`, { headers: { authorization: `Bearer ${seed.publishableKey}` } })).status === 401);

// ---------- Custom wording is used ----------
const custom = { subject: "Your {{app_name}} code: {{code}}", body: "Howdy from {{ app_name }}!\n\n{{code}}\n\nGood for {{expires_minutes}} minutes." };
const saved = await api.emailTemplates.update("verify_email", custom);
check("saving works and marks it custom", saved.custom === true && saved.subject === custom.subject);
const email = `tpl.${Date.now()}@example.com`;
const a = jar();
await a("sign_up", { email, password: "a long enough password" });
await a("email/send_code");
const m1 = await mail(email);
check("the verification email uses the custom wording", m1.startsWith(`Howdy from Templates E2E!`) && /\n\d{6}\n/.test(m1) && m1.includes("Good for 10 minutes."), m1);
check("another instance still gets the default", (await otherApi.emailTemplates.get("verify_email")).custom === false);

await api.emailTemplates.reset("verify_email");
await cache().del(`devmail:${blindIndex(email, "devmail")}`);
await a("email/send_code");
const m2 = await mail(email);
check("after reset, the default wording is back", m2.startsWith("Use this code to verify your email address for Templates E2E"), m2);

// ---------- Sign-in email ----------
await db().execute(sql`update instances set settings = settings || '{"emailCodeSignIn":true}'::jsonb where id = ${seed.instanceId}`);
await invalidateInstance(seed.instanceId);
await api.emailTemplates.update("sign_in", { subject: "Sign in to {{app_name}}", body: "Type {{code}} or tap:\n\n{{link}}" });
await cache().del(`devmail:${blindIndex(email, "devmail")}`);
await jar()("sign_in/email_code", { email });
const m3 = await mail(email);
const code = m3.match(/Type (\d{6}) or tap/)?.[1];
const link = m3.match(/https?:\/\/\S+\/magic-link\?\S+/)?.[0];
check("the sign-in email uses the custom wording, with a working code and link", !!code && !!link, m3);
check("…and the code from it signs in", (await jar()("sign_in/email_code/verify", { email, code })).status === 200);

// ---------- Escaping (the HTML part) ----------
const nasty = renderTemplate(
  { subject: "{{inviter}} invited you", body: "<script>alert(1)</script> <b>{{org_name}}</b>\n\n{{link}}" },
  { inviter: "Eve\r\nBcc: x@example.com", org_name: '<img src=x onerror=alert(1)>', link: 'https://example.com/a"onmouseover="x', link_label: "Accept" },
);
check("developer text is escaped in HTML", !nasty.html.includes("<script>") && nasty.html.includes("&#60;script&#62;") && !nasty.html.includes("<b>"));
check("user-supplied values (org names) are escaped", !nasty.html.includes("<img") && nasty.html.includes("&#60;img"));
check("links can't break out of their attribute", !nasty.html.includes('"onmouseover="') && nasty.html.includes("&#34;onmouseover"));
check("subject newlines from values are flattened", !/[\r\n]/.test(nasty.subject));
check("a {{link}} line becomes a button, a {{code}} line a big code", renderTemplate({ subject: "s", body: "{{code}}\n\n{{link}}" }, { code: "123456", link: "https://x.test/", link_label: "Go" }).html.match(/font-size:28px[^>]*>123456<\/p>[\s\S]*<a href="https:\/\/x.test\/"[^>]*>Go<\/a>/) !== null);

// ---------- Branding ----------
check("invalid color (CSS injection attempt) → 422", await fails(api.emailTemplates.setAccentColor("red; background:url(x)"), "422"));
await api.emailTemplates.setAccentColor("#4f46e5");
const inst = (await getInstance(seed.instanceId))!;
const branded = await composeEmail(inst, "invitation", { org_name: "Acme", inviter: "Ada", link: "https://x.test/i", expires_days: "7" });
check("brand color is used for the button", branded.html.includes("background:#4f46e5"));
await api.emailTemplates.setAccentColor(null);
check("null restores the default color", (await api.emailTemplates.list()).accentColor === null);

// ---------- Dashboard ----------
let denied = false;
try {
  await saveTemplateFor("user_not_an_owner", seed.instanceId, "verify_email", custom);
} catch (e) {
  denied = (e as { status?: number }).status === 404;
}
check("dashboard: a developer who doesn't own the instance can't edit its emails", denied);
let testDenied = false;
try {
  await sendTestEmail("user_not_an_owner", seed.instanceId, "verify_email");
} catch (e) {
  testDenied = (e as { status?: number }).status === 404;
}
check("dashboard: …or send test emails from it", testDenied);
check("every default template passes its own validation", Object.entries(SPECS).every(([, s]) => s.required.every((r) => s.body.includes(`{{${r}}}`))));

await settle();
const audit = (await listAudit(seed.instanceId, { limit: 100 })).data.map((e) => e.type);
check("audit log records template changes", audit.includes("email_template.updated") && audit.includes("email_template.reset"));

await closeDb();
await closeCache();
console.log(failures ? `\n${failures} check(s) failed` : "\nAll email template checks passed");
process.exit(failures ? 1 : 0);
