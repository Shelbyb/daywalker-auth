CREATE TABLE "mfa_sms" (
	"user_id" text PRIMARY KEY NOT NULL,
	"phone_enc" text NOT NULL,
	"phone_index" text NOT NULL,
	"verified_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "mfa_sms" ADD CONSTRAINT "mfa_sms_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;