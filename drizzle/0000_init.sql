CREATE TYPE "public"."environment" AS ENUM('development', 'production');--> statement-breakpoint
CREATE TYPE "public"."session_status" AS ENUM('active', 'ended', 'revoked', 'expired');--> statement-breakpoint
CREATE TABLE "accounts" (
	"id" text PRIMARY KEY NOT NULL,
	"name" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "api_keys" (
	"id" text PRIMARY KEY NOT NULL,
	"instance_id" text NOT NULL,
	"name" text NOT NULL,
	"key_hash" text NOT NULL,
	"key_prefix" text NOT NULL,
	"last_used_at" timestamp with time zone,
	"revoked_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "email_addresses" (
	"id" text PRIMARY KEY NOT NULL,
	"instance_id" text NOT NULL,
	"user_id" text NOT NULL,
	"email_enc" text NOT NULL,
	"email_index" text NOT NULL,
	"is_primary" boolean DEFAULT false NOT NULL,
	"verified_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "instances" (
	"id" text PRIMARY KEY NOT NULL,
	"account_id" text NOT NULL,
	"name" text NOT NULL,
	"environment" "environment" DEFAULT 'development' NOT NULL,
	"allowed_origins" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"settings" jsonb DEFAULT '{"passwordMinLength":8,"sessionLifetimeDays":7,"tokenTtlSeconds":60}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "passwords" (
	"user_id" text PRIMARY KEY NOT NULL,
	"hash" text NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "sessions" (
	"id" text PRIMARY KEY NOT NULL,
	"instance_id" text NOT NULL,
	"user_id" text NOT NULL,
	"refresh_token_hash" text NOT NULL,
	"status" "session_status" DEFAULT 'active' NOT NULL,
	"user_agent_enc" text,
	"ip_address_enc" text,
	"last_active_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "signing_keys" (
	"id" text PRIMARY KEY NOT NULL,
	"instance_id" text NOT NULL,
	"alg" text DEFAULT 'ES256' NOT NULL,
	"public_jwk" jsonb NOT NULL,
	"private_key_enc" text NOT NULL,
	"active" boolean DEFAULT true NOT NULL,
	"retired_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "users" (
	"id" text PRIMARY KEY NOT NULL,
	"instance_id" text NOT NULL,
	"first_name_enc" text,
	"last_name_enc" text,
	"image_url" text,
	"public_metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"private_metadata_enc" text,
	"banned" boolean DEFAULT false NOT NULL,
	"last_sign_in_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "api_keys" ADD CONSTRAINT "api_keys_instance_id_instances_id_fk" FOREIGN KEY ("instance_id") REFERENCES "public"."instances"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "email_addresses" ADD CONSTRAINT "email_addresses_instance_id_instances_id_fk" FOREIGN KEY ("instance_id") REFERENCES "public"."instances"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "email_addresses" ADD CONSTRAINT "email_addresses_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "instances" ADD CONSTRAINT "instances_account_id_accounts_id_fk" FOREIGN KEY ("account_id") REFERENCES "public"."accounts"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "passwords" ADD CONSTRAINT "passwords_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sessions" ADD CONSTRAINT "sessions_instance_id_instances_id_fk" FOREIGN KEY ("instance_id") REFERENCES "public"."instances"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sessions" ADD CONSTRAINT "sessions_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "signing_keys" ADD CONSTRAINT "signing_keys_instance_id_instances_id_fk" FOREIGN KEY ("instance_id") REFERENCES "public"."instances"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "users" ADD CONSTRAINT "users_instance_id_instances_id_fk" FOREIGN KEY ("instance_id") REFERENCES "public"."instances"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "api_keys_hash_idx" ON "api_keys" USING btree ("key_hash");--> statement-breakpoint
CREATE UNIQUE INDEX "email_addresses_instance_email_idx" ON "email_addresses" USING btree ("instance_id","email_index");--> statement-breakpoint
CREATE INDEX "email_addresses_user_idx" ON "email_addresses" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "instances_account_idx" ON "instances" USING btree ("account_id");--> statement-breakpoint
CREATE UNIQUE INDEX "sessions_refresh_hash_idx" ON "sessions" USING btree ("refresh_token_hash");--> statement-breakpoint
CREATE INDEX "sessions_user_idx" ON "sessions" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "signing_keys_instance_idx" ON "signing_keys" USING btree ("instance_id");--> statement-breakpoint
CREATE INDEX "users_instance_idx" ON "users" USING btree ("instance_id");