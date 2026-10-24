CREATE TABLE "audit_chains" (
	"instance_id" text PRIMARY KEY NOT NULL,
	"seq" bigint DEFAULT 0 NOT NULL,
	"hash" text DEFAULT '0000000000000000000000000000000000000000000000000000000000000000' NOT NULL,
	"purged_seq" bigint DEFAULT 0 NOT NULL,
	"purged_hash" text DEFAULT '0000000000000000000000000000000000000000000000000000000000000000' NOT NULL,
	"started_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "audit_export_configs" (
	"instance_id" text PRIMARY KEY NOT NULL,
	"endpoint" text,
	"region" text NOT NULL,
	"bucket" text NOT NULL,
	"prefix" text DEFAULT '' NOT NULL,
	"path_style" boolean DEFAULT false NOT NULL,
	"server_side_encryption" boolean DEFAULT false NOT NULL,
	"access_key_id_enc" text NOT NULL,
	"secret_access_key_enc" text NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"last_pushed_seq" bigint DEFAULT 0 NOT NULL,
	"last_pushed_at" timestamp with time zone,
	"last_error" text,
	"last_error_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "audit_events" ADD COLUMN "seq" bigint;--> statement-breakpoint
ALTER TABLE "audit_events" ADD COLUMN "prev_hash" text;--> statement-breakpoint
ALTER TABLE "audit_events" ADD COLUMN "hash" text;--> statement-breakpoint
ALTER TABLE "audit_events" ADD COLUMN "data_digest" text;--> statement-breakpoint
ALTER TABLE "audit_events" ADD COLUMN "data_erased" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "audit_chains" ADD CONSTRAINT "audit_chains_instance_id_instances_id_fk" FOREIGN KEY ("instance_id") REFERENCES "public"."instances"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "audit_export_configs" ADD CONSTRAINT "audit_export_configs_instance_id_instances_id_fk" FOREIGN KEY ("instance_id") REFERENCES "public"."instances"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "audit_events_seq_idx" ON "audit_events" USING btree ("instance_id","seq");