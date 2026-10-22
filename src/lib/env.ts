import { z } from "zod";

const prod = process.env.NODE_ENV === "production";

const schema = z
  .object({
    DATABASE_URL: z.string().url(),
    // PEM of the Postgres CA (DigitalOcean managed databases). Enables verified TLS without relying on sslmode in the URL.
    DATABASE_CA_CERT: z.string().optional(),
    // Number of trusted reverse-proxy hops in front of the app (client IP = Nth entry from the right of X-Forwarded-For).
    TRUST_PROXY_HOPS: z.string().regex(/^\d{0,2}$/).optional(),
    // Publishable key of the instance that signs developers in to /dashboard (see scripts/bootstrap-platform.ts). Unset = dashboard disabled.
    PLATFORM_PUBLISHABLE_KEY: z.string().regex(/^pk_(test|live)_[A-Za-z0-9_-]+$/).optional().or(z.literal("")),
    VALKEY_URL: z.string().default("redis://localhost:6379"),
    MASTER_KEY: z
      .string()
      .refine((v) => Buffer.from(v, "base64").length === 32, "MASTER_KEY must be 32 random bytes, base64-encoded"),
    // Optional. Pins the key used for lookup indexes so MASTER_KEY can be rotated. See `npm run keys:print-index-key`.
    INDEX_KEY: z
      .string()
      .refine((v) => Buffer.from(v, "base64").length === 32, "INDEX_KEY must be 32 random bytes, base64-encoded")
      .optional()
      .or(z.literal("")),
    APP_URL: z.string().url().default("http://localhost:3000"),
    // "resend" sends real email; "dev" logs to the server console and (outside production) keeps the last code for tests.
    MAIL_TRANSPORT: z.enum(["resend", "dev"]).default("dev"),
    RESEND_API_KEY: z.string().optional(),
    /** Twilio Verify, for SMS two-factor. SMS stays off unless all three are set. */
    TWILIO_ACCOUNT_SID: z.string().regex(/^AC[0-9a-fA-F]{32}$/, "TWILIO_ACCOUNT_SID looks like AC followed by 32 hex characters").optional().or(z.literal("")),
    TWILIO_AUTH_TOKEN: z.string().min(16).optional().or(z.literal("")),
    TWILIO_VERIFY_SERVICE_SID: z.string().regex(/^VA[0-9a-fA-F]{32}$/, "TWILIO_VERIFY_SERVICE_SID looks like VA followed by 32 hex characters").optional().or(z.literal("")),
    MAIL_FROM: z.string().default("Daywalker Auth <no-reply@users.daywalker.dev>"),
  })
  // In production every hop is encrypted: HTTPS for clients, TLS to Postgres and Valkey.
  .superRefine((e, ctx) => {
    if (!prod || process.env.ALLOW_INSECURE_TRANSPORT === "1") return;
    if (!e.APP_URL.startsWith("https://"))
      ctx.addIssue({ code: "custom", path: ["APP_URL"], message: "must be https in production" });
    if (!e.DATABASE_CA_CERT && !/[?&]sslmode=(require|verify-ca|verify-full)\b/.test(e.DATABASE_URL))
      ctx.addIssue({ code: "custom", path: ["DATABASE_URL"], message: "must set sslmode=require (or verify-full) or provide DATABASE_CA_CERT in production" });
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
