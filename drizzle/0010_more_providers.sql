ALTER TYPE "public"."oauth_provider" ADD VALUE 'microsoft';--> statement-breakpoint
ALTER TYPE "public"."oauth_provider" ADD VALUE 'apple';--> statement-breakpoint
ALTER TYPE "public"."oauth_provider" ADD VALUE 'discord';--> statement-breakpoint
ALTER TYPE "public"."oauth_provider" ADD VALUE 'gitlab';--> statement-breakpoint
ALTER TYPE "public"."oauth_provider" ADD VALUE 'oidc';--> statement-breakpoint
ALTER TABLE "oauth_providers" ADD COLUMN "settings" jsonb DEFAULT '{}'::jsonb NOT NULL;