CREATE TABLE "scim_users" (
	"connection_id" text NOT NULL,
	"user_id" text NOT NULL,
	"external_id" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "saml_connections" ADD COLUMN "scim_token_hash" text;--> statement-breakpoint
ALTER TABLE "saml_connections" ADD COLUMN "scim_token_prefix" text;--> statement-breakpoint
ALTER TABLE "saml_connections" ADD COLUMN "scim_token_created_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "scim_users" ADD CONSTRAINT "scim_users_connection_id_saml_connections_id_fk" FOREIGN KEY ("connection_id") REFERENCES "public"."saml_connections"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scim_users" ADD CONSTRAINT "scim_users_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "scim_users_connection_user_idx" ON "scim_users" USING btree ("connection_id","user_id");--> statement-breakpoint
CREATE INDEX "scim_users_user_idx" ON "scim_users" USING btree ("user_id");