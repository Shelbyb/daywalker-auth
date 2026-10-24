CREATE TABLE "satellite_domains" (
	"id" text PRIMARY KEY NOT NULL,
	"instance_id" text NOT NULL,
	"origin" text NOT NULL,
	"hostname" text NOT NULL,
	"verify_token" text NOT NULL,
	"verified_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "satellite_domains" ADD CONSTRAINT "satellite_domains_instance_id_instances_id_fk" FOREIGN KEY ("instance_id") REFERENCES "public"."instances"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "satellite_domains_instance_origin_idx" ON "satellite_domains" USING btree ("instance_id","origin");--> statement-breakpoint
CREATE UNIQUE INDEX "satellite_domains_verified_idx" ON "satellite_domains" USING btree ("origin") WHERE "satellite_domains"."verified_at" is not null;