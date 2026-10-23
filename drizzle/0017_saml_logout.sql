CREATE TABLE "saml_sessions" (
	"session_id" text PRIMARY KEY NOT NULL,
	"connection_id" text NOT NULL,
	"name_id_enc" text NOT NULL,
	"name_id_index" text NOT NULL,
	"name_id_format" text,
	"session_index_enc" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "saml_connections" ADD COLUMN "slo_url" text;--> statement-breakpoint
ALTER TABLE "saml_connections" ADD COLUMN "single_logout" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "saml_connections" ADD COLUMN "sp_key_enc" text;--> statement-breakpoint
ALTER TABLE "saml_connections" ADD COLUMN "sp_cert" text;--> statement-breakpoint
ALTER TABLE "saml_sessions" ADD CONSTRAINT "saml_sessions_session_id_sessions_id_fk" FOREIGN KEY ("session_id") REFERENCES "public"."sessions"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "saml_sessions" ADD CONSTRAINT "saml_sessions_connection_id_saml_connections_id_fk" FOREIGN KEY ("connection_id") REFERENCES "public"."saml_connections"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "saml_sessions_name_idx" ON "saml_sessions" USING btree ("connection_id","name_id_index");