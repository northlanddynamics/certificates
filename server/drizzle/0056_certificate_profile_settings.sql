CREATE TABLE "certificate_profile_settings" (
	"organization_id" text PRIMARY KEY NOT NULL,
	"require_profile" boolean DEFAULT false NOT NULL,
	"updated_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
ALTER TABLE "certificate_profile_settings" ADD CONSTRAINT "certificate_profile_settings_organization_id_organization_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organization"("id") ON DELETE no action ON UPDATE no action;