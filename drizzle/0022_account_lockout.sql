CREATE TABLE "account_lockouts" (
	"user_id" text PRIMARY KEY NOT NULL,
	"instance_id" text NOT NULL,
	"level" integer DEFAULT 0 NOT NULL,
	"locked_at" timestamp with time zone,
	"locked_until" timestamp with time zone,
	"reason" text,
	"unlock_token_hash" text,
	"unlock_expires_at" timestamp with time zone,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "account_lockouts" ADD CONSTRAINT "account_lockouts_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "account_lockouts" ADD CONSTRAINT "account_lockouts_instance_id_instances_id_fk" FOREIGN KEY ("instance_id") REFERENCES "public"."instances"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "account_lockouts_instance_idx" ON "account_lockouts" USING btree ("instance_id");--> statement-breakpoint
CREATE INDEX "account_lockouts_token_idx" ON "account_lockouts" USING btree ("unlock_token_hash");
