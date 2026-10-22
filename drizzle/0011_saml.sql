ALTER TYPE "public"."oauth_provider" ADD VALUE 'saml';--> statement-breakpoint
CREATE TABLE "saml_connections" (
	"id" text PRIMARY KEY NOT NULL,
	"instance_id" text NOT NULL,
	"name" text NOT NULL,
	"org_id" text,
	"idp_entity_id" text NOT NULL,
	"sso_url" text NOT NULL,
	"certificates" jsonb NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "saml_domains" (
	"instance_id" text NOT NULL,
	"domain" text NOT NULL,
	"connection_id" text NOT NULL,
	CONSTRAINT "saml_domains_instance_id_domain_pk" PRIMARY KEY("instance_id","domain")
);
--> statement-breakpoint
ALTER TABLE "saml_connections" ADD CONSTRAINT "saml_connections_instance_id_instances_id_fk" FOREIGN KEY ("instance_id") REFERENCES "public"."instances"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "saml_connections" ADD CONSTRAINT "saml_connections_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "saml_domains" ADD CONSTRAINT "saml_domains_instance_id_instances_id_fk" FOREIGN KEY ("instance_id") REFERENCES "public"."instances"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "saml_domains" ADD CONSTRAINT "saml_domains_connection_id_saml_connections_id_fk" FOREIGN KEY ("connection_id") REFERENCES "public"."saml_connections"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "saml_connections_instance_idx" ON "saml_connections" USING btree ("instance_id");--> statement-breakpoint
CREATE INDEX "saml_domains_connection_idx" ON "saml_domains" USING btree ("connection_id");