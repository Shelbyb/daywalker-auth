import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { publicEnvironment } from "@/lib/auth/environment";

export const OPTIONS = preflight;

/** Public instance settings the UI needs (which sign-in options to show). */
export const GET = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  return ctx.json(await publicEnvironment(ctx.inst));
});
