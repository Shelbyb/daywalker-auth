ALTER TABLE "instances" ADD COLUMN "captcha_secret_enc" text;--> statement-breakpoint
ALTER TABLE "organizations" ADD COLUMN "require_two_factor" boolean DEFAULT false NOT NULL;