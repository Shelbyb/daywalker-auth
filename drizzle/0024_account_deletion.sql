ALTER TABLE "users" ADD COLUMN "deletion_requested_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "deletion_scheduled_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "deletion_token_hash" text;--> statement-breakpoint
CREATE INDEX "users_deletion_due_idx" ON "users" USING btree ("deletion_scheduled_at") WHERE "users"."deletion_scheduled_at" is not null;