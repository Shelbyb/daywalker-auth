import { NextResponse } from "next/server";
import { handler, errors } from "@/lib/http";
import { instanceFromSecretKey } from "@/lib/auth/instance";
import { getTemplate, isTemplateKind, resetTemplate, saveTemplate, SPECS } from "@/lib/email-templates";
import { record } from "@/lib/audit";

type Ctx = { params: Promise<{ kind: string }> };
async function kindOf(ctx: Ctx) {
  const { kind } = await ctx.params;
  if (!isTemplateKind(kind)) throw errors.notFound("Unknown email. Use verify_email, reset_password, sign_in or invitation");
  return kind;
}

export const GET = handler(async (req: Request, ctx: Ctx) => {
  const inst = await instanceFromSecretKey(req);
  const kind = await kindOf(ctx);
  return NextResponse.json({ kind, ...(await getTemplate(inst.id, kind)), placeholders: SPECS[kind].vars, required: SPECS[kind].required });
});

/** Set the subject and body. Plain text with {{placeholders}}; HTML is built for you. */
export const PUT = handler(async (req: Request, ctx: Ctx) => {
  const inst = await instanceFromSecretKey(req);
  const kind = await kindOf(ctx);
  const t = await saveTemplate(inst.id, kind, await req.json());
  void record(inst.id, "email_template.updated", { actor: { type: "api" }, target: kind });
  return NextResponse.json({ kind, ...t });
});

/** Go back to the built-in wording. */
export const DELETE = handler(async (req: Request, ctx: Ctx) => {
  const inst = await instanceFromSecretKey(req);
  const kind = await kindOf(ctx);
  const t = await resetTemplate(inst.id, kind);
  void record(inst.id, "email_template.reset", { actor: { type: "api" }, target: kind });
  return NextResponse.json({ kind, ...t });
});
