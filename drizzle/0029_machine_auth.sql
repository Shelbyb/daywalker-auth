CREATE TABLE "m2m_clients" (
	"id" text PRIMARY KEY NOT NULL,
	"instance_id" text NOT NULL,
	"name" text NOT NULL,
	"secret_hash" text NOT NULL,
	"secret_prefix" text NOT NULL,
	"prev_secret_hash" text,
	"prev_secret_expires_at" timestamp with time zone,
	"scopes" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"token_ttl_seconds" integer DEFAULT 300 NOT NULL,
	"last_used_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "user_api_keys" (
	"id" text PRIMARY KEY NOT NULL,
	"instance_id" text NOT NULL,
	"user_id" text,
	"org_id" text,
	"created_by" text,
	"name" text NOT NULL,
	"key_hash" text NOT NULL,
	"key_prefix" text NOT NULL,
	"scopes" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"expires_at" timestamp with time zone,
	"last_used_at" timestamp with time zone,
	"revoked_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "m2m_clients" ADD CONSTRAINT "m2m_clients_instance_id_instances_id_fk" FOREIGN KEY ("instance_id") REFERENCES "public"."instances"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_api_keys" ADD CONSTRAINT "user_api_keys_instance_id_instances_id_fk" FOREIGN KEY ("instance_id") REFERENCES "public"."instances"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_api_keys" ADD CONSTRAINT "user_api_keys_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_api_keys" ADD CONSTRAINT "user_api_keys_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "m2m_clients_instance_idx" ON "m2m_clients" USING btree ("instance_id");--> statement-breakpoint
CREATE UNIQUE INDEX "user_api_keys_hash_idx" ON "user_api_keys" USING btree ("key_hash");--> statement-breakpoint
CREATE INDEX "user_api_keys_user_idx" ON "user_api_keys" USING btree ("instance_id","user_id");--> statement-breakpoint
CREATE INDEX "user_api_keys_org_idx" ON "user_api_keys" USING btree ("instance_id","org_id");
--> statement-breakpoint
ALTER TABLE "user_api_keys" ADD CONSTRAINT "user_api_keys_one_owner" CHECK (("user_id" IS NULL) <> ("org_id" IS NULL));
