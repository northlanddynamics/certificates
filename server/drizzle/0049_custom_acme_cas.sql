CREATE TABLE "acme_ca" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"organization_id" text NOT NULL,
	"name" text NOT NULL,
	"directory_url" text NOT NULL,
	"tag" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "acme_ca_organization_name_unique" UNIQUE("organization_id","name"),
	CONSTRAINT "acme_ca_tag" CHECK ("acme_ca"."tag" in ('staging', 'production'))
);
--> statement-breakpoint
ALTER TABLE "acme_ca" ADD CONSTRAINT "acme_ca_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE no action ON UPDATE no action;