CREATE TABLE "dns_provider" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" text NOT NULL,
	"name" text NOT NULL,
	"type" text NOT NULL,
	"settings" jsonb NOT NULL,
	"secret_id" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "dns_provider_organization_name_unique" UNIQUE("organization_id","name")
);
--> statement-breakpoint
ALTER TABLE "dns_provider" ADD CONSTRAINT "dns_provider_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "dns_provider" ADD CONSTRAINT "dns_provider_secret_id_organization_id_secret_id_organization_id_fk" FOREIGN KEY ("secret_id","organization_id") REFERENCES "public"."secret"("id","organization_id") ON DELETE no action ON UPDATE no action;