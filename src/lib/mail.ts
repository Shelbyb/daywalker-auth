import { env } from "./env";
import { cache } from "./cache";
import { blindIndex } from "./crypto";

type Mail = { to: string; subject: string; text: string; html: string };

export const escapeHtml = (s: string) => s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

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
