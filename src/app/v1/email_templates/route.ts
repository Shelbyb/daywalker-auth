import { NextResponse } from "next/server";
import { handler } from "@/lib/http";
import { instanceFromSecretKey } from "@/lib/auth/instance";
import { listTemplates } from "@/lib/email-templates";

/** Backend API: every email's current wording (custom or default) and the placeholders it accepts. */
export const GET = handler(async (req: Request) => {
  const inst = await instanceFromSecretKey(req);
  const data = (await listTemplates(inst.id)).map((t) => ({ kind: t.kind, subject: t.subject, body: t.body, custom: t.custom, placeholders: t.vars, required: t.required, updatedAt: t.updatedAt }));
  return NextResponse.json({ data, accentColor: inst.settings.emailAccentColor ?? null });
});
