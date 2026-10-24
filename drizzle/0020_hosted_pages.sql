CREATE TABLE "custom_domains" (
	"id" text PRIMARY KEY NOT NULL,
	"instance_id" text NOT NULL,
	"hostname" text NOT NULL,
	"verify_token" text NOT NULL,
	"verified_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "custom_domains" ADD CONSTRAINT "custom_domains_instance_id_instances_id_fk" FOREIGN KEY ("instance_id") REFERENCES "public"."instances"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "custom_domains_hostname_idx" ON "custom_domains" USING btree ("hostname");--> statement-breakpoint
CREATE INDEX "custom_domains_instance_idx" ON "custom_domains" USING btree ("instance_id");