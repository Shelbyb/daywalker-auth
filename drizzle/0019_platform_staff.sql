CREATE TYPE "public"."platform_role" AS ENUM('admin', 'user');--> statement-breakpoint
CREATE TABLE "platform_audit_events" (
	"id" text PRIMARY KEY NOT NULL,
	"type" text NOT NULL,
	"actor_id" text,
	"instance_id" text,
	"target_id" text,
	"data_enc" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "platform_settings" (
	"id" text PRIMARY KEY NOT NULL,
	"mail_from" text,
	"resend_api_key_enc" text,
	"twilio_account_sid" text,
	"twilio_auth_token_enc" text,
	"twilio_verify_service_sid" text,
	"updated_by" text,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "platform_staff" (
	"user_id" text PRIMARY KEY NOT NULL,
	"role" "platform_role" DEFAULT 'user' NOT NULL,
	"created_by" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "sessions" ADD COLUMN "impersonator_id" text;--> statement-breakpoint
CREATE INDEX "platform_audit_created_idx" ON "platform_audit_events" USING btree ("created_at");--> statement-breakpoint
CREATE INDEX "platform_audit_type_idx" ON "platform_audit_events" USING btree ("type","created_at");