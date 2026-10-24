CREATE TABLE "org_domains" (
	"id" text PRIMARY KEY NOT NULL,
	"instance_id" text NOT NULL,
	"org_id" text NOT NULL,
	"domain" text NOT NULL,
	"verification_token" text NOT NULL,
	"verified_at" timestamp with time zone,
	"verified_via" text,
	"enrollment" text DEFAULT 'none' NOT NULL,
	"role" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "org_roles" (
	"instance_id" text NOT NULL,
	"key" text NOT NULL,
	"name" text NOT NULL,
	"description" text,
	"permissions" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "org_roles_instance_id_key_pk" PRIMARY KEY("instance_id","key")
);
--> statement-breakpoint
ALTER TABLE "invitations" ALTER COLUMN "role" DROP DEFAULT;--> statement-breakpoint
ALTER TABLE "memberships" ALTER COLUMN "role" DROP DEFAULT;--> statement-breakpoint
ALTER TABLE "invitations" ALTER COLUMN "role" SET DATA TYPE text;--> statement-breakpoint
ALTER TABLE "invitations" ALTER COLUMN "role" SET DEFAULT 'member';--> statement-breakpoint
ALTER TABLE "memberships" ALTER COLUMN "role" SET DATA TYPE text;--> statement-breakpoint
ALTER TABLE "memberships" ALTER COLUMN "role" SET DEFAULT 'member';--> statement-breakpoint
ALTER TABLE "org_domains" ADD CONSTRAINT "org_domains_instance_id_instances_id_fk" FOREIGN KEY ("instance_id") REFERENCES "public"."instances"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "org_domains" ADD CONSTRAINT "org_domains_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "org_roles" ADD CONSTRAINT "org_roles_instance_id_instances_id_fk" FOREIGN KEY ("instance_id") REFERENCES "public"."instances"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "org_domains_org_domain_idx" ON "org_domains" USING btree ("org_id","domain");--> statement-breakpoint
CREATE UNIQUE INDEX "org_domains_verified_idx" ON "org_domains" USING btree ("instance_id","domain") WHERE "org_domains"."verified_at" is not null;--> statement-breakpoint
CREATE INDEX "org_domains_instance_idx" ON "org_domains" USING btree ("instance_id");--> statement-breakpoint
DROP TYPE "public"."org_role";