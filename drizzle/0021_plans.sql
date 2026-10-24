CREATE TABLE "plans" (
	"id" text PRIMARY KEY NOT NULL,
	"slug" text NOT NULL,
	"name" text NOT NULL,
	"description" text DEFAULT '' NOT NULL,
	"price_cents" bigint DEFAULT 0 NOT NULL,
	"interval" text DEFAULT 'month' NOT NULL,
	"stripe_price_id" text,
	"features" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"active" boolean DEFAULT true NOT NULL,
	"is_default" boolean DEFAULT false NOT NULL,
	"sort_order" bigint DEFAULT 0 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX "plans_slug_idx" ON "plans" USING btree ("slug");--> statement-breakpoint
CREATE TABLE "subscriptions" (
	"account_id" text PRIMARY KEY NOT NULL,
	"plan_id" text NOT NULL,
	"stripe_customer_id" text,
	"stripe_subscription_id" text,
	"status" text DEFAULT 'active' NOT NULL,
	"current_period_end" timestamp with time zone,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "subscriptions" ADD CONSTRAINT "subscriptions_account_id_accounts_id_fk" FOREIGN KEY ("account_id") REFERENCES "public"."accounts"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "subscriptions" ADD CONSTRAINT "subscriptions_plan_id_plans_id_fk" FOREIGN KEY ("plan_id") REFERENCES "public"."plans"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
INSERT INTO "plans" ("id","slug","name","description","price_cents","features","is_default","sort_order") VALUES ('plan_free','free','Free','For side projects and trying things out.',0,'[]'::jsonb,true,0);--> statement-breakpoint
INSERT INTO "plans" ("id","slug","name","description","price_cents","features","sort_order") VALUES ('plan_pro','pro','Pro','Custom session claims, inactivity timeouts and more.',2500,'["session_customization","organization_settings","custom_domain"]'::jsonb,1);
