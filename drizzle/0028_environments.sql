CREATE TABLE "applications" (
	"id" text PRIMARY KEY NOT NULL,
	"account_id" text NOT NULL,
	"name" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "instances" ADD COLUMN "application_id" text;--> statement-breakpoint
ALTER TABLE "applications" ADD CONSTRAINT "applications_account_id_accounts_id_fk" FOREIGN KEY ("account_id") REFERENCES "public"."accounts"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "applications_account_idx" ON "applications" USING btree ("account_id");--> statement-breakpoint
ALTER TABLE "instances" ADD CONSTRAINT "instances_application_id_applications_id_fk" FOREIGN KEY ("application_id") REFERENCES "public"."applications"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
INSERT INTO "applications" ("id", "account_id", "name", "created_at") SELECT 'app_' || substr(md5("id" || 'application'), 1, 22), "account_id", "name", "created_at" FROM "instances";--> statement-breakpoint
UPDATE "instances" SET "application_id" = 'app_' || substr(md5("id" || 'application'), 1, 22);--> statement-breakpoint
CREATE UNIQUE INDEX "instances_application_env_idx" ON "instances" USING btree ("application_id","environment") WHERE "instances"."application_id" is not null;