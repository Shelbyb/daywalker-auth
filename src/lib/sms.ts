/**
 * Twilio Verify: Twilio creates, sends and checks the codes (with its own fraud protection), so
 * no SMS code is ever stored here. Configured once per deployment; SMS is unavailable without it.
 */
import { env } from "./env";
import { guardedFetch } from "./net-guard";

export const smsConfigured = () => {
  const e = env();
  return !!(e.TWILIO_ACCOUNT_SID && e.TWILIO_AUTH_TOKEN && e.TWILIO_VERIFY_SERVICE_SID);
};

/** Tests point this at a local mock; never allowed on an HTTPS deployment. */
function base() {
  const t = process.env.TWILIO_TEST_BASE_URL;
  if (t) {
    if (env().APP_URL.startsWith("https://")) throw new Error("TWILIO_TEST_BASE_URL is not allowed on an HTTPS deployment");
    return t.replace(/\/$/, "");
  }
  return "https://verify.twilio.com";
}

async function call(path: string, form: Record<string, string>) {
  const e = env();
  const r = await guardedFetch(`${base()}/v2/Services/${e.TWILIO_VERIFY_SERVICE_SID}/${path}`, {
    method: "POST",
    headers: {
      authorization: `Basic ${Buffer.from(`${e.TWILIO_ACCOUNT_SID}:${e.TWILIO_AUTH_TOKEN}`).toString("base64")}`,
      "content-type": "application/x-www-form-urlencoded",
      accept: "application/json",
    },
    body: new URLSearchParams(form).toString(),
    timeoutMs: 8000,
  });
  let body: Record<string, unknown> = {};
  try {
    body = JSON.parse(r.text);
  } catch {
    /* non-JSON error page */
  }
  return { status: r.status, body };
}

/** Sends a code. Returns false if Twilio refused (bad number, blocked country, too many attempts). */
export async function sendSmsCode(phone: string) {
  const r = await call("Verifications", { To: phone, Channel: "sms" });
  if (r.status >= 200 && r.status < 300) return true;
  console.warn("[sms] send refused:", r.status, String(r.body.code ?? ""));
  return false;
}

/** True only if Twilio approves this code for this number. Each code works once. */
export async function checkSmsCode(phone: string, code: string) {
  if (!/^\d{4,10}$/.test(code)) return false;
  const r = await call("VerificationCheck", { To: phone, Code: code });
  return r.status >= 200 && r.status < 300 && r.body.status === "approved";
}

/** Normalizes to E.164 (+ and 8 to 15 digits). Throws on anything else. */
export function normalizePhone(raw: string) {
  const p = raw.replace(/[\s().-]/g, "");
  if (!/^\+[1-9]\d{7,14}$/.test(p)) return null;
  return p;
}

/** "•••• 4567": enough to recognise, not enough to reuse. */
export const maskPhone = (p: string) => `•••• ${p.slice(-4)}`;
