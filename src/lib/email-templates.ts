/**
 * Per-instance email wording. Developers write plain text with {{placeholders}}; we build the
 * HTML. Nothing they type is ever treated as HTML (everything is escaped), only known
 * placeholders are allowed, and each kind of email must keep the placeholders it can't work
 * without (a sign-in email with no code is useless).
 */
import { and, eq } from "drizzle-orm";
import { z } from "zod";
import { db, schema } from "./db";
import { errors } from "./http";
import { escapeHtml } from "./mail";
import type { Instance } from "./db/schema";

export const TEMPLATE_KINDS = ["verify_email", "reset_password", "sign_in", "invitation", "account_unlock"] as const;
export type TemplateKind = (typeof TEMPLATE_KINDS)[number];

type Spec = { label: string; vars: string[]; required: string[]; subject: string; body: string };

export const SPECS: Record<TemplateKind, Spec> = {
  verify_email: {
    label: "Email verification",
    vars: ["app_name", "code", "expires_minutes"],
    required: ["code"],
    subject: "{{code}} is your {{app_name}} verification code",
    body: "Use this code to verify your email address for {{app_name}}:\n\n{{code}}\n\nIt expires in {{expires_minutes}} minutes. If you didn't create an account, you can ignore this email.",
  },
  reset_password: {
    label: "Password reset",
    vars: ["app_name", "code", "expires_minutes"],
    required: ["code"],
    subject: "Reset your {{app_name}} password",
    body: "Use this code to reset your password for {{app_name}}:\n\n{{code}}\n\nIt expires in {{expires_minutes}} minutes. If you didn't request this, you can ignore this email. Your password won't change.",
  },
  sign_in: {
    label: "Sign-in code and link",
    vars: ["app_name", "code", "link", "expires_minutes"],
    required: ["code", "link"],
    subject: "{{code}} is your {{app_name}} sign-in code",
    body: "Sign in to {{app_name}} with this code:\n\n{{code}}\n\nOr use this link:\n\n{{link}}\n\nBoth expire in {{expires_minutes}} minutes and work once. If you didn't try to sign in, you can ignore this email. Never share this code with anyone.",
  },
  invitation: {
    label: "Organization invitation",
    vars: ["app_name", "org_name", "inviter", "link", "expires_days"],
    required: ["link"],
    subject: "{{inviter}} invited you to join {{org_name}} on {{app_name}}",
    body: "{{inviter}} invited you to join {{org_name}} on {{app_name}}.\n\n{{link}}\n\nThe link works for {{expires_days}} days. If you weren't expecting this, you can ignore this email.",
  },
  account_unlock: {
    label: "Account locked",
    vars: ["app_name", "link", "expires_hours"],
    required: ["link"],
    subject: "Your {{app_name}} account is temporarily locked",
    body: "There were too many failed attempts to sign in to your {{app_name}} account, so we locked it for a while.\n\nIf this was you, unlock it now:\n\n{{link}}\n\nThe link works once and expires in {{expires_hours}} hours. If it wasn't you, your password is safe; we recommend resetting it.",
  },
};

const PLACEHOLDER = /\{\{\s*([a-z_]+)\s*\}\}/g;
const DEFAULT_ACCENT = "#14121a";
export const accentInput = z.string().regex(/^#[0-9a-fA-F]{6}$/, "Use a hex color like #4f46e5");

export const templateInput = z.object({
  subject: z.string().trim().min(1, "Subject is required").max(200),
  body: z.string().trim().min(1, "Body is required").max(5000),
});

/** Throws a field-level 400 if the text uses unknown placeholders or drops a required one. */
export function validateTemplate(kind: TemplateKind, input: { subject: string; body: string }) {
  const spec = SPECS[kind];
  const t = templateInput.parse(input);
  if (/[\r\n]/.test(t.subject)) throw errors.badRequest("invalid_template", "The subject must be a single line");
  for (const [field, text] of [["subject", t.subject], ["body", t.body]] as const) {
    for (const m of text.matchAll(PLACEHOLDER))
      if (!spec.vars.includes(m[1]))
        throw errors.badRequest("invalid_template", `Unknown placeholder {{${m[1]}}} in the ${field}. You can use: ${spec.vars.map((v) => `{{${v}}}`).join(", ")}`);
  }
  for (const v of spec.required)
    if (!new RegExp(`\\{\\{\\s*${v}\\s*\\}\\}`).test(t.body))
      throw errors.badRequest("invalid_template", `The body must include {{${v}}}`);
  return t;
}

const fill = (text: string, vars: Record<string, string>) => text.replace(PLACEHOLDER, (_, k: string) => vars[k] ?? "");

/** Builds the text and HTML parts. A paragraph that is just {{code}} or {{link}} gets special styling. */
export function renderTemplate(t: { subject: string; body: string }, vars: Record<string, string>, accent = DEFAULT_ACCENT) {
  const color = accentInput.safeParse(accent).success ? accent : DEFAULT_ACCENT;
  const subject = fill(t.subject, vars).replace(/[\r\n]+/g, " ").slice(0, 200);
  const text = fill(t.body, vars);
  const paragraphs = t.body.split(/\n\s*\n/).map((p) => p.trim()).filter(Boolean);
  const html = paragraphs
    .map((p) => {
      if (/^\{\{\s*code\s*\}\}$/.test(p) && vars.code)
        return `<p style="font-size:28px;letter-spacing:6px;font-weight:700;margin:24px 0">${escapeHtml(vars.code)}</p>`;
      if (/^\{\{\s*link\s*\}\}$/.test(p) && vars.link)
        return `<p style="margin:24px 0"><a href="${escapeHtml(vars.link)}" style="background:${color};color:#fff;padding:10px 16px;border-radius:8px;text-decoration:none">${escapeHtml(vars.link_label ?? "Open link")}</a></p>`;
      // Escape the developer's text first, then drop in escaped values; a link becomes an anchor.
      const parts = p.split(PLACEHOLDER);
      const out = parts
        .map((seg, i) => {
          if (i % 2 === 0) return escapeHtml(seg).replace(/\n/g, "<br>");
          const v = vars[seg] ?? "";
          return seg === "link" && v ? `<a href="${escapeHtml(v)}" style="color:${color}">${escapeHtml(v)}</a>` : escapeHtml(v);
        })
        .join("");
      return `<p>${out}</p>`;
    })
    .join("\n");
  return {
    subject,
    text,
    html: `<div style="font-family:system-ui,sans-serif;max-width:420px;margin:auto;padding:24px;color:#14121a;line-height:1.5">${html}</div>`,
  };
}

export async function getTemplate(instanceId: string, kind: TemplateKind) {
  const [row] = await db()
    .select()
    .from(schema.emailTemplates)
    .where(and(eq(schema.emailTemplates.instanceId, instanceId), eq(schema.emailTemplates.kind, kind)));
  return row ? { subject: row.subject, body: row.body, custom: true, updatedAt: row.updatedAt } : { subject: SPECS[kind].subject, body: SPECS[kind].body, custom: false, updatedAt: null };
}

export async function listTemplates(instanceId: string) {
  return Promise.all(TEMPLATE_KINDS.map(async (kind) => ({ kind, ...SPECS[kind], defaultSubject: SPECS[kind].subject, defaultBody: SPECS[kind].body, ...(await getTemplate(instanceId, kind)) })));
}

export async function saveTemplate(instanceId: string, kind: TemplateKind, input: { subject: string; body: string }) {
  const t = validateTemplate(kind, input);
  await db()
    .insert(schema.emailTemplates)
    .values({ instanceId, kind, subject: t.subject, body: t.body })
    .onConflictDoUpdate({ target: [schema.emailTemplates.instanceId, schema.emailTemplates.kind], set: { subject: t.subject, body: t.body, updatedAt: new Date() } });
  return getTemplate(instanceId, kind);
}

export async function resetTemplate(instanceId: string, kind: TemplateKind) {
  await db().delete(schema.emailTemplates).where(and(eq(schema.emailTemplates.instanceId, instanceId), eq(schema.emailTemplates.kind, kind)));
  return getTemplate(instanceId, kind);
}

export const isTemplateKind = (k: string): k is TemplateKind => (TEMPLATE_KINDS as readonly string[]).includes(k);

const LINK_LABEL: Partial<Record<TemplateKind, (v: Record<string, string>) => string>> = {
  sign_in: (v) => `Sign in to ${v.app_name}`,
  invitation: () => "Accept invitation",
  account_unlock: () => "Unlock my account",
};

/** What every sender calls: the instance's wording (or the default), filled in and rendered. */
export async function composeEmail(inst: Instance, kind: TemplateKind, vars: Record<string, string>) {
  const t = await getTemplate(inst.id, kind);
  const all = { app_name: inst.name, ...vars };
  return renderTemplate(t, { ...all, link_label: LINK_LABEL[kind]?.(all) ?? "Open link" }, inst.settings.emailAccentColor);
}

/** Sample values for previews and test sends. */
export const SAMPLE_VARS = (appName: string): Record<string, string> => ({
  app_name: appName,
  code: "123456",
  link: "https://users.daywalker.dev/example-link",
  expires_minutes: "10",
  expires_days: "7",
  expires_hours: "24",
  org_name: "Acme Inc.",
  inviter: "Ada Lovelace",
});
