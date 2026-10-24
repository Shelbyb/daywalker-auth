/**
 * Platform staff checks: staff access to customer instances, impersonation sessions (private to the
 * platform audit log), the platform audit log itself, and platform settings (encrypted, env fallback).
 * Calls the lib directly, like dashboard-e2e. Needs Postgres and Valkey; the server isn't required.
 */
import { and, eq, sql } from "drizzle-orm";
import { seedInstance } from "./seed";
import { db, schema, closeDb } from "../src/lib/db";
import { closeCache } from "../src/lib/cache";
import { ApiError } from "../src/lib/http";
import { ENCRYPTED_FIELDS } from "../src/lib/crypto-fields";

let failures = 0;
const check = (name: string, ok: boolean, detail?: unknown) => {
  console.log(`${ok ? "✓" : "✗"} ${name}${ok ? "" : ` — ${JSON.stringify(detail)}`}`);
  if (!ok) failures++;
};
const status = async (fn: () => Promise<unknown>) => {
  try {
    await fn();
    return 0;
  } catch (e) {
    return e instanceof ApiError ? e.status : -1;
  }
};

const platform = await seedInstance("Platform (test)", ["http://localhost:3000"]);
process.env.PLATFORM_PUBLISHABLE_KEY = platform.publishableKey;
const D = await import("../src/lib/dashboard");
const { platformRole } = await import("../src/lib/platform-staff");
const { recordPlatform, listPlatformAudit } = await import("../src/lib/platform-audit");
const S = await import("../src/lib/auth/sessions");
const { listSessions } = await import("../src/lib/auth/account");
const { getInstance } = await import("../src/lib/auth/instance");
const PS = await import("../src/lib/platform-settings");

const stamp = Date.now();
const owner = `user_owner${stamp}`, stranger = `user_stranger${stamp}`, staff = `user_staff${stamp}`;

// ---------- Staff access to customer instances ----------
const mine = await D.createInstance(owner, { name: "Customer app", environment: "development" });
check("a stranger can't open someone else's instance", (await status(() => D.instanceDetails(stranger, mine.id))) === 404);
check("not staff by default", (await platformRole(staff)) === null);
await db().insert(schema.platformStaff).values({ userId: staff, role: "user", createdBy: "test" });
check("staff role is read back", (await platformRole(staff)) === "user");
check("platform staff can open any customer instance", (await D.instanceDetails(staff, mine.id)).id === mine.id);
check("viewingAsStaff is true for staff on someone else's instance", await D.viewingAsStaff(staff, mine.id));
check("viewingAsStaff is false for the owner", !(await D.viewingAsStaff(owner, mine.id)));
check("staff still can't open the platform instance through the dashboard", (await status(() => D.instanceDetails(staff, platform.instanceId))) === 404);
await new Promise((r) => setTimeout(r, 300));
const accessed = await listPlatformAudit({ type: "instance.accessed", actor: staff });
check("staff access is recorded in the platform audit log", accessed.data.some((e) => e.instanceId === mine.id));
await D.instanceDetails(staff, mine.id);
await new Promise((r) => setTimeout(r, 300));
check("access is recorded at most once an hour per instance", (await listPlatformAudit({ type: "instance.accessed", actor: staff, instance: mine.id })).data.length === 1);
const instAudit = await D.auditFor(owner, mine.id, {});
check("the customer's audit log doesn't show staff access", !instAudit.data.some((e) => e.actor.id === staff));
await db().delete(schema.platformStaff).where(eq(schema.platformStaff.userId, staff));
check("removing staff takes effect at once", (await status(() => D.instanceDetails(staff, mine.id))) === 404);

// ---------- Impersonation sessions ----------
const inst = (await getInstance(mine.id))!;
const [{ id: userId }] = await db().insert(schema.users).values({ id: `user_t${stamp}`, instanceId: inst.id }).returning({ id: schema.users.id });
const before = await D.auditFor(owner, mine.id, { target: userId });
const s = await S.createSession(inst, userId, { ip: "203.0.113.9", userAgent: "test", impersonatorId: staff, lifetimeMs: 30 * 60_000 });
check("impersonation session lasts the requested time", Math.abs(s.expiresAt.getTime() - Date.now() - 30 * 60_000) < 5000);
const [row] = await db().select().from(schema.sessions).where(eq(schema.sessions.id, s.id));
check("session records who impersonated", row.impersonatorId === staff);
const tok = await S.issueToken(inst, s.refreshToken);
check("impersonation session can mint a token for the user", tok.userId === userId && typeof tok.jwt === "string");
check("the token carries no impersonation claim", !JSON.parse(Buffer.from(tok.jwt.split(".")[1], "base64url").toString()).act);
await new Promise((r) => setTimeout(r, 300));
const after = await D.auditFor(owner, mine.id, { target: userId });
check("no sign-in entry in the customer's audit log", after.data.length === before.data.length);
const [u] = await db().select({ last: schema.users.lastSignInAt }).from(schema.users).where(eq(schema.users.id, userId));
check("impersonation doesn't count as the user's sign-in", u.last === null);
const own = await S.createSession(inst, userId, { ip: "203.0.113.10", userAgent: "own" });
check("the user's session list hides the impersonation session", !(await listSessions(inst.id, userId, own.id)).some((x) => x.id === s.id));
check("…but shows it to the impersonation session itself", (await listSessions(inst.id, userId, s.id)).some((x) => x.id === s.id && x.current));
await S.endSession(inst.id, s.refreshToken);
await new Promise((r) => setTimeout(r, 300));
check("ending it adds no sign-out entry for the customer", !(await D.auditFor(owner, mine.id, { type: "user.signed_out", target: userId })).data.length);
check("an ended impersonation session can't mint tokens", (await status(() => S.issueToken(inst, s.refreshToken))) === 401);

// ---------- Platform audit log ----------
await recordPlatform("impersonation.started", { actorId: staff, instanceId: inst.id, target: userId, data: { reason: "Support ticket 42", userEmail: "secret@example.com" } });
await new Promise((r) => setTimeout(r, 300));
const started = await listPlatformAudit({ type: "impersonation.started", actor: staff });
check("impersonation is listed with its reason", started.data[0]?.data?.reason === "Support ticket 42");
const raw = await db().execute(sql`select data_enc from platform_audit_events where actor_id = ${staff} and type = 'impersonation.started'`);
check("platform audit details are encrypted at rest", raw.length === 1 && !JSON.stringify(raw).includes("secret@example.com"));
check("platform audit filters by instance", (await listPlatformAudit({ instance: inst.id })).data.every((e) => e.instanceId === inst.id));

// ---------- Platform settings ----------
const resendKey = `re_test${stamp}abcdef`;
const twilioToken = `tok${stamp}abcdefghijkl`;
await db().delete(schema.platformSettings);
PS.invalidatePlatformSettings();
const envOnly = await PS.effectiveSettings();
check("without saved settings, the environment is used", envOnly.mailFrom === (process.env.MAIL_FROM || "Daywalker Auth <no-reply@users.daywalker.dev>"));
check("bad Twilio SID rejected", (await status(() => PS.savePlatformSettings(staff, { twilioAccountSid: "nope" }))) === -1);
const changed = await PS.savePlatformSettings(staff, {
  mailFrom: "Acme <no-reply@acme.test>",
  resendApiKey: resendKey,
  twilioAccountSid: "AC" + "a".repeat(32),
  twilioAuthToken: twilioToken,
  twilioVerifyServiceSid: "VA" + "b".repeat(32),
});
check("changed fields are reported by name", changed.includes("resendApiKey") && changed.includes("twilioAuthToken"));
const eff = await PS.effectiveSettings();
check("saved settings take effect", eff.mailFrom === "Acme <no-reply@acme.test>" && eff.resendApiKey === resendKey && eff.twilio?.authToken === twilioToken);
const settingsRaw = JSON.stringify(await db().execute(sql`select * from platform_settings`));
check("secrets are encrypted at rest", !settingsRaw.includes(resendKey) && !settingsRaw.includes(twilioToken));
const view = await PS.platformSettingsView();
check("the settings view never returns secrets", !JSON.stringify(view).includes(resendKey) && !JSON.stringify(view).includes(twilioToken) && view.resendApiKey === "saved");
check("saving again with empty secrets keeps them", (await PS.savePlatformSettings(staff, { mailFrom: "Acme <no-reply@acme.test>", twilioAccountSid: "AC" + "a".repeat(32), twilioVerifyServiceSid: "VA" + "b".repeat(32) })).length === 0 && (await PS.effectiveSettings()).resendApiKey === resendKey);
await PS.savePlatformSettings(staff, { clearResendApiKey: true, clearTwilioAuthToken: true });
const cleared = await PS.effectiveSettings();
check("clearing falls back to the environment", cleared.resendApiKey === (process.env.RESEND_API_KEY || null) && (cleared.twilio === null) === !process.env.TWILIO_AUTH_TOKEN);
check("new encrypted columns are in the rotation registry", ["platform_audit_events.data_enc", "platform_settings.resend_api_key_enc", "platform_settings.twilio_auth_token_enc"].every((c) => ENCRYPTED_FIELDS.some((f) => `${f.table}.${f.column}` === c)));
await db().delete(schema.platformSettings);

// ---------- Cleanup ----------
await db().delete(schema.platformAuditEvents).where(eq(schema.platformAuditEvents.actorId, staff));
await db().delete(schema.instances).where(and(eq(schema.instances.id, mine.id)));

console.log(failures ? `\n${failures} check(s) failed` : "\nAll platform checks passed");
await closeDb();
await closeCache();
process.exit(failures ? 1 : 0);
