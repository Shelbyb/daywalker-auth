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

// Country calling codes are prefix-free: no code starts another. So a number is in a country iff it
// starts with "+" and that code. We accept only codes of a valid shape (checked against the leading
// digits that real 1-, 2- and 3-digit codes use) so a typo like "4" can't quietly allow dozens of countries.
const ONE = new Set(["1", "7"]);
const TWO = new Set("20 27 30 31 32 33 34 36 39 40 41 43 44 45 46 47 48 49 51 52 53 54 55 56 57 58 60 61 62 63 64 65 66 81 82 84 86 90 91 92 93 94 95 98".split(" "));
const THREE_LEAD = new Set("21 22 23 24 25 26 28 29 35 37 38 42 50 59 67 68 69 80 85 87 88 96 97 99".split(" "));

export function validCallingCode(code: string) {
  if (!/^\d{1,3}$/.test(code)) return false;
  if (code.length === 1) return ONE.has(code);
  if (code.length === 2) return TWO.has(code);
  return THREE_LEAD.has(code.slice(0, 2));
}

/** Cleans "+1, 44  49" into ["1","44","49"], or throws a message for the first bad entry. */
export function parseCallingCodes(raw: string[]) {
  const out = new Set<string>();
  for (const part of raw.flatMap((r) => r.split(/[\s,;]+/))) {
    const c = part.replace(/^\+/, "");
    if (!c) continue;
    if (!validCallingCode(c)) throw new Error(`"${part}" isn't a country calling code. Use codes like 1, 44 or 49`);
    out.add(c);
  }
  if (out.size > 100) throw new Error("Too many countries");
  return [...out];
}

/** No list (or an empty one) means every country. */
export function phoneInAllowedCountry(phone: string, codes: string[] | undefined) {
  if (!codes?.length) return true;
  return codes.some((c) => phone.startsWith(`+${c}`));
}

/** "•••• 4567": enough to recognise, not enough to reuse. */
export const maskPhone = (p: string) => `•••• ${p.slice(-4)}`;
