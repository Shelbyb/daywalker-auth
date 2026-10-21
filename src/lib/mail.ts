import { env } from "./env";
import { cache } from "./cache";
import { blindIndex } from "./crypto";

type Mail = { to: string; subject: string; text: string; html: string };

const escapeHtml = (s: string) => s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

/** Code emails. Plain layout, no tracking pixels or remote images. */
export function codeEmail(kind: "verify" | "reset", appName: string, code: string): Omit<Mail, "to"> {
  const what = kind === "verify" ? "verify your email address" : "reset your password";
  const subject = kind === "verify" ? `${code} is your ${appName} verification code` : `Reset your ${appName} password`;
  const tail =
    kind === "reset"
      ? "If you didn't request this, you can ignore this email. Your password won't change."
      : "If you didn't create an account, you can ignore this email.";
  const text = `Use this code to ${what} for ${appName}:\n\n${code}\n\nIt expires in 10 minutes. ${tail}`;
  const html = `<div style="font-family:system-ui,sans-serif;max-width:420px;margin:auto;padding:24px;color:#14121a">
<p>Use this code to ${what} for <strong>${escapeHtml(appName)}</strong>:</p>
<p style="font-size:28px;letter-spacing:6px;font-weight:700;margin:24px 0">${code}</p>
<p style="color:#78716c;font-size:13px">It expires in 10 minutes. ${tail}</p></div>`;
  return { subject, text, html };
}

export async function sendMail(mail: Mail) {
  const e = env();
  if (e.MAIL_TRANSPORT === "resend") {
    const res = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { authorization: `Bearer ${e.RESEND_API_KEY}`, "content-type": "application/json" },
      body: JSON.stringify({ from: e.MAIL_FROM, to: [mail.to], subject: mail.subject, text: mail.text, html: mail.html }),
    });
    if (!res.ok) throw new Error(`Mail send failed: ${res.status}`);
    return;
  }
  // Dev transport: never enabled in production (env validation enforces resend there).
  console.info(`[mail:dev] to=${mail.to} subject="${mail.subject}"`);
  await cache().set(`devmail:${blindIndex(mail.to, "devmail")}`, mail.text, "EX", 600);
}
