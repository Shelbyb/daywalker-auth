import { z } from "zod";

const prod = process.env.NODE_ENV === "production";

const schema = z
  .object({
    DATABASE_URL: z.string().url(),
    VALKEY_URL: z.string().default("redis://localhost:6379"),
    MASTER_KEY: z
      .string()
      .refine((v) => Buffer.from(v, "base64").length === 32, "MASTER_KEY must be 32 random bytes, base64-encoded"),
    APP_URL: z.string().url().default("http://localhost:3000"),
    // "resend" sends real email; "dev" logs to the server console and (outside production) keeps the last code for tests.
    MAIL_TRANSPORT: z.enum(["resend", "dev"]).default("dev"),
    RESEND_API_KEY: z.string().optional(),
    MAIL_FROM: z.string().default("Daywalker Auth <no-reply@auth.daywalker.dev>"),
  })
  // In production every hop is encrypted: HTTPS for clients, TLS to Postgres and Valkey.
  .superRefine((e, ctx) => {
    if (!prod || process.env.ALLOW_INSECURE_TRANSPORT === "1") return;
    if (!e.APP_URL.startsWith("https://"))
      ctx.addIssue({ code: "custom", path: ["APP_URL"], message: "must be https in production" });
    if (!/[?&]sslmode=(require|verify-ca|verify-full)\b/.test(e.DATABASE_URL))
      ctx.addIssue({ code: "custom", path: ["DATABASE_URL"], message: "must set sslmode=verify-full (or require) in production" });
    if (e.MAIL_TRANSPORT !== "resend" || !e.RESEND_API_KEY)
      ctx.addIssue({ code: "custom", path: ["MAIL_TRANSPORT"], message: "must be resend (with RESEND_API_KEY) in production" });
    if (!e.VALKEY_URL.startsWith("rediss://"))
      ctx.addIssue({ code: "custom", path: ["VALKEY_URL"], message: "must use rediss:// (TLS) in production" });
  });

let cached: z.infer<typeof schema> | undefined;
/** Validated lazily so `next build` doesn't need runtime secrets. */
export function env() {
  return (cached ??= schema.parse(process.env));
}
