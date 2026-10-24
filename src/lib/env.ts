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
      .refine((v) => Buffer.from(v, "base64").length === 48, "MASTER_KEY must be 48 random bytes, base64-encoded (openssl rand -base64 48)"),
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
    /** Twilio Verify, for SMS two-factor. Defaults for the platform settings; SMS stays off unless all three are set (here or there). */
    TWILIO_ACCOUNT_SID: z.string().regex(/^AC[0-9a-fA-F]{32}$/, "TWILIO_ACCOUNT_SID looks like AC followed by 32 hex characters").optional().or(z.literal("")),
    TWILIO_AUTH_TOKEN: z.string().min(16).optional().or(z.literal("")),
    TWILIO_VERIFY_SERVICE_SID: z.string().regex(/^VA[0-9a-fA-F]{32}$/, "TWILIO_VERIFY_SERVICE_SID looks like VA followed by 32 hex characters").optional().or(z.literal("")),
    MAIL_FROM: z.string().default("Daywalker Auth <no-reply@users.daywalker.dev>"),
    /**
     * Cloudflare Turnstile for the platform's own sign-in and sign-up pages (the dashboard). On only
     * when the secret is set. TURNSTILE_HOSTNAMES: comma-separated hostnames the widget may be solved
     * on (defaults to APP_URL's hostname); never list localhost on a production deployment.
     */
    TURNSTILE_SITE_KEY: z.string().max(200).default("0x4AAAAAAFjRgGz7X9Ig6AM3"),
    TURNSTILE_SECRET: z.string().max(200).optional().or(z.literal("")),
    /** Stripe billing for developer plans; off unless STRIPE_SECRET_KEY is set. */
    STRIPE_SECRET_KEY: z.string().max(300).optional().or(z.literal("")),
    STRIPE_WEBHOOK_SECRET: z.string().max(300).optional().or(z.literal("")),
    TURNSTILE_HOSTNAMES: z.string().max(2000).optional().or(z.literal("")),
  })
  // In production every hop is encrypted: HTTPS for clients, TLS to Postgres and Valkey.
  .superRefine((e, ctx) => {
    if (!prod || process.env.ALLOW_INSECURE_TRANSPORT === "1") return;
    if (!e.APP_URL.startsWith("https://"))
      ctx.addIssue({ code: "custom", path: ["APP_URL"], message: "must be https in production" });
    if (!e.DATABASE_CA_CERT && !/[?&]sslmode=(require|verify-ca|verify-full)\b/.test(e.DATABASE_URL))
      ctx.addIssue({ code: "custom", path: ["DATABASE_URL"], message: "must set sslmode=require (or verify-full) or provide DATABASE_CA_CERT in production" });
    // The Resend key itself may come from the platform settings (dashboard) instead of RESEND_API_KEY.
    if (e.MAIL_TRANSPORT !== "resend")
      ctx.addIssue({ code: "custom", path: ["MAIL_TRANSPORT"], message: "must be resend in production" });
    if (!e.VALKEY_URL.startsWith("rediss://"))
      ctx.addIssue({ code: "custom", path: ["VALKEY_URL"], message: "must use rediss:// (TLS) in production" });
  });

let cached: z.infer<typeof schema> | undefined;
/** Validated lazily so `next build` doesn't need runtime secrets. */
export function env() {
  return (cached ??= schema.parse(process.env));
}
